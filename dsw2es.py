#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import requests
import json
import sys
import elasticsearch
from elasticsearch import Elasticsearch
import os
from dotenv import load_dotenv
import logging

# Read variables from dotenv
load_dotenv()
esurl = os.getenv("ELASTIC_URL")
esport = os.getenv("ELASTIC_PORT")
esindex = os.getenv("ELASTIC_INDEX_NAME")
esuser = os.getenv("ELASTIC_USER")
espw = os.getenv("ELASTIC_PW")
dswurl = os.getenv("DSW_URL")
dswuser = os.getenv("DSW_USER")
dswpw = os.getenv("DSW_PW")
logfile = os.getenv("LOGFILE")

# Create and configure logger
logging.basicConfig(filename=logfile,
                    format='%(asctime)s %(message)s',
                    filemode='a')

# Creating an object
logger = logging.getLogger()

# Setting the threshold of logger to DEBUG
logger.setLevel(logging.WARNING)

logger.warning('Trying to update the ' + esindex + ' index.')

# Authorize with DSW
dsw_token = ''
try:
    dsw_authurl = dswurl + '/tokens'
    auth_data = dict(email=dswuser, password=dswpw)
    data_auth = requests.post(url=dsw_authurl, json=auth_data, headers={'Accept': 'application/json'}).text
    data_auth = json.loads(data_auth)
    dsw_token = data_auth['token']
except requests.exceptions.HTTPError as e:
    print('Could not authenticate with DSW, user: ' + dswuser + ' , existing.')
    logger.error('Could not authenticate with DSW, user: ' + dswuser + ' , exiting: ' + e.response.text)
    sys.exit(1)

headers = {'Accept': 'application/json',
           'Authorization': 'Bearer ' + dsw_token}

# Create new index (or replace existing)
elastic = Elasticsearch([{'host': esurl, 'port': esport, 'use_ssl': True}], http_auth=(esuser, espw))
try:
    create_resp = elastic.indices.create(index=esindex, ignore=[400, 404])
    # print(create_resp)
    logger.info('Index ' + esindex + ' was successfully created.')
except elasticsearch.exceptions.RequestError as e:
    if e.error == 'resource_already_exists_exception':
        # print('We will ignore this')
        pass  # Index already exists. Ignore, it will be recreated.
    else:  # Other exception - raise it
        logger.error('Index ' + esindex + ' could not be created: ' + e.error)
        raise e
        sys.exit()

# Request data from DSW as string
dsw_geturl = dswurl + '/questionnaires'
data = requests.get(url=dsw_geturl, headers=headers).text

# convert string to Json
data = json.loads(data)

# debug
# print(data)

dmp = {}
count = 0
madmp_schema = "https://github.com/RDA-DMP-Common/RDA-DMP-Common-Standard/tree/master/examples/JSON/JSSON-schema/1.0"

for i in data['_embedded']['questionnaires']:
    d = dict()
    md = dict()
    d['schema'] = madmp_schema
    dmp_id = i['uuid']
    created_at = i['createdAt']
    if i['updatedAt']:
        updated_at = i['updatedAt']
        d['modified'] = updated_at
    is_outdated = 'false'
    if 'state' in i:
        state = i['state']
        if state == 'Outdated':
            is_outdated = 'true'

    is_template = i['isTemplate']
    dmp_name = i['name']

    # Which DMPs to include in index?
    rules = [not is_template,
             is_outdated == 'false']

    if all(rules):
        print('{}, {}'.format(dmp_id, dmp_name))
        # Add to json output

        d['title'] = dmp_name
        d['created'] = created_at
        di = {"identifier": "https://dsw-staging.ita.chalmers.se/projects/" + dmp_id, "type": "url"}

        d['dmp_identifier'] = di

        if i['package']:
            d[
                'description'] = "This DMP has been created using Chalmers Data Stewardship Wizard (dsw.chalmers.se) and is based on the knowledge model " + \
                                 i['package']['name'] + " (" + i['package']['id'] + ")."
            if "swe" in i['package']['id']:
                d['language'] = 'swe'
            else:
                d['language'] = 'eng'

        md['id'] = dmp_id
        if state:
            md['state'] = state
        if 'visibility' in i:
            md['visibility'] = i['visibility']
        if 'sharing' in i:
            md['sharing'] = i['sharing']
        if 'description' in i:
            md['description'] = i['description']

        # request full doc from DSW
        link_full = dswurl + '/questionnaires/' + str(dmp_id)

        # debug
        # print ('link full: {}'.format(link_full))

        # Retrieve full DMP record from API
        try:
            data_full = requests.get(url=link_full, headers=headers).text
            data_full = json.loads(data_full)
        except requests.exceptions.HTTPError as e:
            print('Could not retrieve record id: ' + dmp_id + ' , existing.')
            logger.error('Could not retrieve record id: ' + dmp_id + ' , existing: ' + e.response.text)
            sys.exit(1)

        # Contact and contributor(s)

        if '1e85da40-bbfc-4180-903e-6c569ed2da38.73d686bd-7939-412e-8631-502ee6d9ea7b' in data_full['replies']:
            contributors = data_full['replies'][
                '1e85da40-bbfc-4180-903e-6c569ed2da38.73d686bd-7939-412e-8631-502ee6d9ea7b']

            if contributors:
                cs = []
                for c in contributors['value']['value']:
                    ct = {}
                    affiliation_node = ''

                    contributor = '1e85da40-bbfc-4180-903e-6c569ed2da38.73d686bd-7939-412e-8631-502ee6d9ea7b.' + c
                    try:
                        name_node = contributor + ".6155ad47-3d1e-4488-9f2a-742de1e56580"
                        contributor_name = data_full['replies'][name_node]['value']['value']
                        ct["name"] = contributor_name
                    except KeyError:
                        contributor_name = ''
                    try:
                        email_node = contributor + ".3a2ffc13-6a0e-4976-bb34-14ab6d938348"
                        contributor_email = data_full['replies'][email_node]['value']['value']
                        ct["mbox"] = contributor_email
                    except KeyError:
                        contributor_email = ''
                    try:
                        orcid_node = contributor + ".6295a55d-48d7-4f3c-961a-45b38eeea41f"
                        contributor_orcid = data_full['replies'][orcid_node]['value']['value']
                        ct["contributor_id"] = {"identifier": contributor_orcid, "type": "orcid"}
                    except KeyError:
                        contributor_orcid = ''
                    try:
                        ct["affiliation"] = {}
                        affiliation_node = contributor + '.68530470-1f1c-4448-8593-63a288713a66';
                        # print('aff node: ' + affiliation_node)
                        # Non-standard field (CTH)

                        if affiliation_node + '.d8efc3fb-9717-4566-9529-e89e71b1554d.d9c9674e-aa62-429f-a9b1-f2d151122249' in \
                                data_full['replies']:
                            ct["affiliation"] = {"name": "Chalmers University of Technology",
                                                 "affiliation_id": {"name": "https://ror.org/040wg7k59", "type": "ror"}}
                        if affiliation_node in data_full['replies'] and data_full['replies'][affiliation_node]['value'][
                            'value'] == '7f0c9b48-4f8c-46b7-be12-3fbc39287482':
                            ct["affiliation"] = {"name": "University of Gothenburg",
                                                 "affiliation_id": {"name": "https://ror.org/01tm6cn81", "type": "ror"}}
                        if affiliation_node + '.f970e56e-da9d-4a00-b559-223890056e24.c10690e4-df79-4ce0-859a-cc176b5597ca' in \
                                data_full['replies']:
                            affiliation_other = affiliation_node + '.f970e56e-da9d-4a00-b559-223890056e24.c10690e4-df79-4ce0-859a-cc176b5597ca'
                            affiliation_other_name = data_full['replies'][affiliation_other]['value']['value']['value']
                            affiliation_other_id = data_full['replies'][affiliation_other]['value']['value']['id']
                            ct["affiliation"] = {"name": affiliation_other_name,
                                                 "affiliation_id": {"name": affiliation_other_id, "type": "ror"}}
                            print('aff: ' + contributor_name + ', ' + str(ct['affiliation']))
                    except KeyError:
                        print('no affiliations');
                        ct["affiliation"] = {}
                    try:
                        role_node = contributor + ".829dcda6-db8a-40ac-819a-92b9b52490f5"
                        role_id = data_full['replies'][role_node]['value']['value']
                        if role_id == 'f7468e79-c621-4ac9-95e0-263ebdf23c73':
                            cc = {}
                            contributor_role = 'contact person'
                            if contributor_orcid:
                                cc['contact_id'] = {"identifier": contributor_orcid, "type": "orcid"}
                            cc['affiliation'] = ct['affiliation']
                            cc['name'] = contributor_name
                            if contributor_email:
                                cc['email'] = contributor_email
                        elif role_id == 'fe411838-170e-45d7-9d91-14f95ad347e6':
                            contributor_role = 'data collector'
                        elif role_id == '0ee99167-c1a2-4fe9-a799-ef07a31ccf35':
                            contributor_role = 'data curator'
                        elif role_id == '3eec8106-b82c-4ce4-8fde-0a5270c55b10':
                            contributor_role = 'data steward'
                        elif role_id == '369db75c-cf52-459a-836c-e3bcac3590bb':
                            contributor_role = 'researcher'
                        elif role_id == 'dead02bb-d5b2-4036-9e99-3318f191b3d0':
                            contributor_role = 'other'
                        else:
                            contributor_role = 'other'
                    except KeyError:
                        contributor_role = '(unknown)'
                    ct["role"] = [contributor_role]

                    cs.append(ct)

            d["contributor"] = cs
            if cc:
                d["contact"] = cc

        # Projects and funding

        md['hasProject'] = 'false'

        if '1e85da40-bbfc-4180-903e-6c569ed2da38.c3dabaaf-c946-4a0d-889c-ede966f97667' in data_full['replies']:
            projects = data_full['replies']['1e85da40-bbfc-4180-903e-6c569ed2da38.c3dabaaf-c946-4a0d-889c-ede966f97667']

            if projects:
                ps = []
                md['hasProject'] = 'true'
                for p in projects['value']['value']:
                    pt = {}
                    project = '1e85da40-bbfc-4180-903e-6c569ed2da38.c3dabaaf-c946-4a0d-889c-ede966f97667.' + p
                    try:
                        pname_node = project + ".f0ef08fd-d733-465c-bc66-5de0b826c41b"
                        pname = data_full['replies'][pname_node]['value']['value']
                        pt["title"] = pname
                    except KeyError:
                        pname = ''
                    try:
                        pdesc_node = project + ".22583d74-3c98-4e0a-b363-26d767c88212"
                        pdesc = data_full['replies'][pdesc_node]['value']['value']
                        pdesc = pdesc.replace('\n', ' ')
                        pt["description"] = pdesc
                    except KeyError:
                        pdesc = ''
                    try:
                        pstart_node = project + ".de84b9b5-bcd0-4954-8370-72ea83916b8c"
                        pstart = data_full['replies'][pstart_node]['value']['value']
                        pt["start"] = pstart
                    except KeyError:
                        pstart = ''
                    try:
                        pend_node = project + ".cabc6f07-6015-454e-b97a-c34db4ec0c60"
                        pend = data_full['replies'][pend_node]['value']['value']
                        pt["end"] = pend
                    except KeyError:
                        pend = ''
                    try:
                        pfunding_node = project + ".36a87eac-402d-43fb-a0df-ac5963bdf87d"
                        pfl = []
                        for pf in data_full['replies'][pfunding_node]['value']['value']:
                            pfn = {}
                            funding = pfunding_node + '.' + pf
                            # print('funding: ' + funding)
                            try:
                                pf_funder_node = funding + ".0b12fb8c-ee0f-40c0-9c53-b6826b786a0c"
                                pf_funder = data_full['replies'][pf_funder_node]['value']['value']['id']
                                pf_funder_name = data_full['replies'][pf_funder_node]['value']['value']['value']
                                pfn['funder_name'] = pf_funder_name
                                if pf_funder_name == 'Vetenskapsrådet':
                                    pfn['funder_id'] = {'identifier': 'https://ror.org/03zttf063', 'type': 'ror'}
                                else:
                                    pfn['funder_id'] = {'identifier': pf_funder, 'type': 'url'}
                            except KeyError:
                                pfunder = ''
                            try:
                                pf_grant_node = funding + ".1ccbd0bb-4263-4240-9dc5-936ef09eef53"
                                pf_grant = data_full['replies'][pf_grant_node]['value']['value']
                                pfn['grant_id'] = {'identifier': pf_grant, 'type': 'other'}
                            except KeyError:
                                pfunder = ''
                            try:
                                pf_status_node = funding + ".54ff3b18-652f-4235-8f9f-3c87e2d63169"
                                pf_status_id = data_full['replies'][pf_status_node]['value']['value']
                                if pf_status_id == 'dcbeab22-d188-4fa0-b50b-5c9d1a2fbefe':
                                    pf_status = 'granted'
                                elif pf_status_id == '85fad342-a89d-414b-bc83-286a7417bb78':
                                    pf_status = 'applied'
                                elif pf_status_id == '59ed0193-8211-4ee8-8d36-0640d99ce870':
                                    pf_status = 'planned'
                                else:
                                    pf_status = 'unknown'
                                pfn['funding_status'] = pf_status
                            except KeyError:
                                pf_status_id = ''

                            pfl.append(pfn)

                        pt['funding'] = pfl
                    except KeyError:
                        print('no funding')

                    try:
                        if pt['funding']:
                            ps.append(pt)
                    except KeyError:
                        print('nothing to add')

            d['project'] = ps

        # Ethical issues

        ethical_issues_exist = 'unknown'

        # GDPR
        if '8eb418fe-f415-44cd-8027-5fac5fc025c1.ab5a4fb6-0717-410d-91b1-f47998659572' in data_full['replies']:
            if \
                    data_full['replies']['8eb418fe-f415-44cd-8027-5fac5fc025c1.ab5a4fb6-0717-410d-91b1-f47998659572'][
                        'value']['value'] == 'd2c27c85-8e39-4a24-a483-3ca5156b5fc6':
                ethical_issues_exist = 'yes'
                md['hasPersonalData'] = 'true'
                if '8eb418fe-f415-44cd-8027-5fac5fc025c1.ab5a4fb6-0717-410d-91b1-f47998659572.d2c27c85-8e39-4a24-a483-3ca5156b5fc6.41d5be8f-cc0c-4f8f-a20a-980e5d44609d' in \
                        data_full['replies']:
                    ethical_issues_desc = data_full['replies'][
                        '8eb418fe-f415-44cd-8027-5fac5fc025c1.ab5a4fb6-0717-410d-91b1-f47998659572.d2c27c85-8e39-4a24-a483-3ca5156b5fc6.41d5be8f-cc0c-4f8f-a20a-980e5d44609d'][
                        'value']['value']
                    d['ethical_issues_description'] = ethical_issues_desc
            if \
                    data_full['replies']['8eb418fe-f415-44cd-8027-5fac5fc025c1.ab5a4fb6-0717-410d-91b1-f47998659572'][
                        'value'][
                        'value'] == '43dd8b13-633f-4d06-9f45-4365e748da71':
                ethical_issues_exist = 'no'
                ethical_issues_exist = 'false'

        d['ethical_issues_exist'] = ethical_issues_exist

        # Dataset(s)

        md['hasDatasets'] = 'false'

        if 'd5b27482-b598-4b8c-b534-417d4ad27394.4e0c1edf-660c-4ebf-81f5-9fa959dead30' in data_full['replies']:
            datasets = data_full['replies']['d5b27482-b598-4b8c-b534-417d4ad27394.4e0c1edf-660c-4ebf-81f5-9fa959dead30']

            if datasets:
                dsts = []
                md['hasDatasets'] = 'true'
                dstname = ''
                for dst in \
                        data_full['replies'][
                            'd5b27482-b598-4b8c-b534-417d4ad27394.4e0c1edf-660c-4ebf-81f5-9fa959dead30'][
                            'value']['value']:

                    dset = {}
                    dataset = 'd5b27482-b598-4b8c-b534-417d4ad27394.4e0c1edf-660c-4ebf-81f5-9fa959dead30.' + dst
                    try:
                        dstname_node = dataset + ".b0949d09-d179-4491-9fb4-14b0deb9f862"
                        dstname = data_full['replies'][dstname_node]['value']['value']
                        dset["title"] = dstname
                    except KeyError:
                        dstname = ''
                    try:
                        dstdesc_node = dataset + ".205a886d-83d7-4359-ae63-7103e05357c3"
                        dstdesc = data_full['replies'][dstdesc_node]['value']['value']
                        dset["description"] = dstdesc
                    except KeyError:
                        dstdesc = ''
                    try:
                        dstpersdata_node = dataset + ".a1d76760-053c-4706-80a2-cfb6c6a061f3"
                        dstpersdata_id = data_full['replies'][dstpersdata_node]['value']['value']
                        if dstpersdata_id == '0cdc4817-7c54-4ec1-b2f4-5c007a85c7b8':
                            dstpersdata = 'yes'
                        elif dstpersdata_id == '4b2a08c7-4942-41fc-8114-d3868c882624':
                            dstpersdata = 'no'
                        else:
                            dstpersdata = 'unknown'
                        dset['personal_data'] = dstpersdata
                    except KeyError:
                        dstpersdata = ''
                    try:
                        dstsensdata_node = dataset + ".cc95b399-7d8d-4232-bccf-686f78c91bff"
                        dstsensdata_id = data_full['replies'][dstsensdata_node]['value']['value']
                        if dstsensdata_id == '2686575d-cd74-4e2c-8524-eaca6f510425':
                            dstsensdata = 'yes'
                        elif dstsensdata_id == '60de66a3-d303-4784-8931-bc58f8a3e747':
                            dstsensdata = 'no'
                        else:
                            dstsensdata = 'unknown'
                        dset['sensitive_data'] = dstsensdata
                    except KeyError:
                        dstsensdata = ''
                    try:
                        dstid_node = dataset + ".cf727a0a-78c4-45a7-aa9b-cf7650ae873a"
                        for dist in data_full['replies'][dstid_node]['value']['value']:
                            dset_dist = {}
                            dataset_dist = dataset + '.cf727a0a-78c4-45a7-aa9b-cf7650ae873a.' + dist
                            try:
                                dist_dset_id_type_node = dataset_dist + ".5c22cf59-89e3-43a1-af10-1af43a97bcb2"
                                dist_dset_id_type = data_full['replies'][dist_dset_id_type_node]['value']['value']
                                if dist_dset_id_type == '48062bc9-0ffb-4509-bec6-e90641a30569':
                                    dist_dset_type = 'doi'
                                elif dist_dset_id_type == 'b93a037a-006a-486f-87e0-6bef5c28879b':
                                    dist_dset_type = 'handle'
                                elif dist_dset_id_type == '7a1d3b28-5f85-48b8-b052-2448c276d9fc':
                                    dist_dset_type = 'url'
                                elif dist_dset_id_type == 'c353f027-823b-4242-9149-37dca26cf4bc':
                                    dist_dset_type = 'ark'
                                elif dist_dset_id_type == '97236701-7b62-40f8-99a0-3b18d3fe3658':
                                    dist_dset_type = 'other'
                                else:
                                    dist_dset_type = 'unknown'
                                dist_dset_id_node = dataset_dist + ".9e13b2d3-5f00-4e19-8a52-5c33c5b1cb07"
                                dist_dset_id = data_full['replies'][dist_dset_id_node]['value']['value']
                                dset["dataset_id"] = {'identifier': dist_dset_id, 'type': dist_dset_type}
                            except KeyError:
                                dist_dset_id = ''
                    except:
                        print()

                    # Only add dataset if there is a dataset title (correct?)
                    if dstname:
                        dsts.append(dset)

                    if dsts:
                        d['datasets'] = dsts
                        print('dataset added')
        else:
            print('NO DATASETS')

        # Additional metadata (local)

        md['hasExistingData'] = 'false'
        if '82fd0cce-2b41-423f-92ad-636d0872045c.efc80cc8-8318-4f8c-acb7-dc1c60e491c1' in data_full['replies']:
            if data_full['replies']['82fd0cce-2b41-423f-92ad-636d0872045c.efc80cc8-8318-4f8c-acb7-dc1c60e491c1']['value']['value'] == '2663b978-5125-4224-9930-0a50dbe895c9':
                md['hasExistingData'] = 'true'

        md['hasCollectingNewData'] = 'false'
        if 'b1df3c74-0b1f-4574-81c4-4cc2d780c1af.f87c331d-794a-42c8-a910-61a2a9110dab' in data_full['replies']:
            if \
            data_full['replies']['b1df3c74-0b1f-4574-81c4-4cc2d780c1af.f87c331d-794a-42c8-a910-61a2a9110dab']['value'][
                'value'] == 'e4ca2d31-137a-46d3-96cd-3e9e8c5e9a76':
                md['hasCollectingNewData'] = 'true'

        md['hasCreatingNewData'] = 'false'
        if 'b1df3c74-0b1f-4574-81c4-4cc2d780c1af.0561d9e5-8bbe-49c7-a656-5714d3c94078' in data_full['replies']:
            if \
                    data_full['replies']['b1df3c74-0b1f-4574-81c4-4cc2d780c1af.0561d9e5-8bbe-49c7-a656-5714d3c94078'][
                        'value'][
                        'value'] == '65da7ae7-5062-4667-9cb2-86c5d17c4473':
                md['hasCreatingNewData'] = 'true'

        md['hasNonEquipmentNewData'] = 'false'
        if 'b1df3c74-0b1f-4574-81c4-4cc2d780c1af.f038bd46-ee4e-4f53-b7ea-482381c2c855' in data_full['replies']:
            if \
                    data_full['replies']['b1df3c74-0b1f-4574-81c4-4cc2d780c1af.f038bd46-ee4e-4f53-b7ea-482381c2c855'][
                        'value'][
                        'value'] == '4fd89b13-f33c-4858-8b25-ab6da271efc6':
                md['hasNonEquipmentNewData'] = 'true'

        if '10a10ffd-bfe1-4c6b-bbb6-3dfb1e63a5d5.b7cb30ba-acb9-439e-88e0-08e2658b779e' in data_full['replies']:
            storage_needs_id = \
                data_full['replies']['10a10ffd-bfe1-4c6b-bbb6-3dfb1e63a5d5.b7cb30ba-acb9-439e-88e0-08e2658b779e'][
                    'value'][
                    'value']
            if storage_needs_id == '62eb65fb-1a5f-49d1-b294-acad3a42b23b':
                storage_needs = 'Very small, < 1 TB'
            elif storage_needs_id == 'c51174aa-647e-4a1e-9bd9-92c33de956f2':
                storage_needs = 'Small (1-5 TB)'
            elif storage_needs_id == 'c0e59c38-89a0-408f-8c29-ead561d3e7d4':
                storage_needs = 'Large (5-50 TB)'
            elif storage_needs_id == 'c13357bd-fe0f-4443-86be-ee3a523b624b':
                storage_needs = 'Very large (>= 50 TB)'
            else:
                storage_needs = 'unknown'
            md['storage_needs'] = storage_needs

        if '10a10ffd-bfe1-4c6b-bbb6-3dfb1e63a5d5.1cc02007-5443-49f2-ba73-216d6f5b1f4f' in data_full['replies']:
            storage_needs_id = \
                data_full['replies']['10a10ffd-bfe1-4c6b-bbb6-3dfb1e63a5d5.1cc02007-5443-49f2-ba73-216d6f5b1f4f'][
                    'value'][
                    'value']
            if storage_needs_id == '863fec5d-9338-402e-8363-cbc60a657a6b':
                storage_needs = 'Very small, < 1 TB'
            elif storage_needs_id == '936f61af-b5f9-4064-874f-3aec8661783d':
                storage_needs = 'Small (1-5 TB)'
            elif storage_needs_id == '0d5ca8f6-1b7d-4e8c-8286-890adeac89d0':
                storage_needs = 'Large (5-50 TB)'
            elif storage_needs_id == 'd190654f-d9b5-4f1f-993c-8b8324a1447a':
                storage_needs = 'Very large (>= 50 TB)'
            else:
                storage_needs = 'unknown'
            md['storage_needs'] = storage_needs

        dmp['dmp'] = d
        dmp['metadata'] = md

        # convert to json
        dmp_json = json.dumps(dmp)

        # debug
        # print(dmp_json)

        # PUT (POST) update to ES index
        # https://www.elastic.co/guide/en/elasticsearch/client/python-api/current/index.html
        # https://kb.objectrocket.com/elasticsearch/how-to-index-elasticsearch-documents-using-the-python-client-library

        try:
            response = elastic.index(index=esindex, doc_type='dmp', id=dmp_id, document=dmp, ignore=[400, 404])
        except elasticsearch.exceptions.RequestError as e:
            if e.error == 'resource_already_exists_exception':
                pass  # Doc already exists. Ignore, it will be updated.
            else:  # Other exception - raise it
                logger.error('Error when writing doc id: ' + dmp_id + ' to index.' + e.error)
                raise e
                sys.exit()

        print('\n')
        count += 1

logger.warning('Successfully indexed ' + str(count) + ' items.')
print('Successfully indexed ' + str(count) + ' items. Exiting now.')
sys.exit()
