#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import configparser
import datetime
import logging
import os
import pathlib
import sys
import uuid

import dotenv
import elasticsearch
import requests


class Config:
    ENCODING = 'utf-8'
    MADMP_SCHEMA_URL = 'https://github.com/RDA-DMP-Common/RDA-DMP-Common-Standard/tree/master/examples/JSON/JSON-schema/1.1'

    ES_URL = os.getenv('ELASTIC_URL')
    ES_PORT = int(os.getenv('ELASTIC_PORT'))
    ES_INDEX = os.getenv('ELASTIC_INDEX_NAME')
    ES_USERNAME = os.getenv('ELASTIC_USER')
    ES_PASSWORD = os.getenv('ELASTIC_PW')
    DSW_URL = os.getenv('DSW_BASE_URL')
    DSW_API_URL = f'{DSW_URL}/wizard-api'
    DSW_PROJECTS_URL = f'{DSW_URL}/wizard/projects/'
    DSW_API_KEY = os.getenv('DSW_API_KEY')
    LOG_FILE = os.getenv('LOGFILE', 'dsw2es.log')
    LOG_LEVEL = os.getenv('LOGLEVEL', 'INFO')
    CONFIG_FILE = os.getenv('CONFIG_FILE', 'dsw2es.conf')
    LAST_RUN_FILE = os.getenv('LAST_RUN_FILE', 'lastrun.txt')
    FULL_RUN = os.getenv('FULL_RUN', 'False').lower() in ['true', 'yes', '1']


    def __init__(self):
        self.config = configparser.ConfigParser()
        self.logger = None
        self._init_logging()
        self._load_config()

    def _load_config(self):
        file = pathlib.Path(self.CONFIG_FILE)
        if not file.exists():
            raise FileNotFoundError(f'Config file {self.CONFIG_FILE} not found.')
        self.config.read(file)

    def _init_logging(self):
        logging.basicConfig(
            filename=self.LOG_FILE,
            format='%(asctime)s %(message)s',
            filemode='a',
        )
        self.logger = logging.getLogger('DSW2ES')
        self.logger.setLevel(self.LOG_LEVEL)
        self.logger.addHandler(logging.StreamHandler(sys.stdout))
        self.logger.warning(f'Trying to update the {self.ES_INDEX} index.')

    @property
    def es_hosts(self):
        return [{
            'host': self.ES_URL,
            'port': self.ES_PORT,
            'use_ssl': self.ES_URL.startswith('https')},
        ]


class DSW2ES:
    # TODO: exception handling
    # TODO: code style
    # TODO: unify logging

    def __init__(self, config: Config):
        self.config = config
        self.logger = config.logger

        self.dsw_session = requests.Session()
        self.dsw_session.headers.update({
            'Accept': 'application/json',
            'Authorization': f'Bearer {self.config.DSW_API_KEY}',
        })

        self.elastic = elasticsearch.Elasticsearch(
            hosts=self.config.es_hosts,
            http_auth=(self.config.ES_USERNAME, self.config.ES_PASSWORD),
        )

    def run(self):
        last_run_file = pathlib.Path(self.config.LAST_RUN_FILE)
        try:
            last_run_str = last_run_file.read_text(encoding=self.config.ENCODING)
            last_run = datetime.datetime.fromisoformat(last_run_str)
        except Exception:
            last_run = None

        if self.config.FULL_RUN:
            last_run = None

        new_last_run_str = str(datetime.datetime.now(tz=datetime.UTC).isoformat())
        self._run(last_run)
        last_run_file.write_text(new_last_run_str, encoding=self.config.ENCODING)

    def _run(self, last_run_at=None):
        # TODO: order by updatedAt and break instead of continue
        self._prepare_es_index()

        questionnaires = self._fetch_dsw_questionnaires()
        for questionnaire in questionnaires:
            # Check rules
            state = questionnaire.get('state', 'unknown')
            is_template = questionnaire['isTemplate']

            if state == 'Outdated' or is_template:
                self.logger.info('Skipping outdated or template DMP: %s', questionnaire['uuid'])
                continue

            updated_at = datetime.datetime.fromisoformat(questionnaire['updatedAt'])
            if last_run_at is not None and updated_at <= last_run_at:
                self.logger.info('Skipping DMP %s, not updated since last run.', questionnaire['uuid'])
                continue

            # Prepare data and metadata
            data, metadata = dict(), dict()
            self._questionnaire_basic(data, metadata, questionnaire)
            questionnaire_full = self._fetch_dsw_questionnaire(questionnaire['uuid'])
            self._questionnaire_details(data, metadata, questionnaire_full)
            data = {
                'dmp': data,
                'metadata': metadata,
            }

            # Push to ES
            self._push_dmp_to_es(questionnaire['uuid'], data)

    def _prepare_es_index(self):
        try:
            self.elastic.indices.create(
                index=self.config.ES_INDEX,
                ignore=[400, 404],
            )
            self.config.logger.info(f'Index {self.config.ES_INDEX} was successfully created.')
        except elasticsearch.exceptions.RequestError as e:
            if e.error == 'resource_already_exists_exception':
                pass
            else:
                self.config.logger.error(f'Index {self.config.ES_INDEX} could not be created: {e.error}')
                raise e

    def _push_dmp_to_es(self, dmp_id, data):
        try:
            response = self.elastic.index(
                index=self.config.ES_INDEX,
                doc_type='dmp',
                id=dmp_id,
                document=data,
                ignore=[400, 404],
            )
        except elasticsearch.exceptions.RequestError as e:
            if e.error == 'resource_already_exists_exception':
                print(dmp_id + ' already exists.')
                pass  # Doc already exists. Ignore, it will be updated.
            else:  # Other exception - raise it
                self.logger.error('Error when writing doc id: ' + dmp_id + ' to index.' + e.error)
                print('Error when writing doc id: ' + dmp_id + ' to index.' + e.error)
                raise e

    def _fetch_dsw_questionnaires(self):
        response = self.dsw_session.get(
            url=f'{self.config.DSW_API_URL}/questionnaires',
            params={
                'isTemplate': 'false',
                'sort': 'createdAt,desc',
                'size': 500,
            },
        )
        response.raise_for_status()
        return response.json()['_embedded']['questionnaires']

    def _fetch_dsw_questionnaire(self, dmp_id):
        try:
            response = self.dsw_session.get(
                url=f'{self.config.DSW_API_URL}/questionnaires/{dmp_id}/questionnaire',
            )
            response.raise_for_status()
            return response.json()
        except requests.exceptions.HTTPError as e:
            print('Could not retrieve record id: ' + dmp_id + ' , existing.')
            self.config.logger.error('Could not retrieve record id: ' + dmp_id + ' , existing: ' + e.response.text)
            sys.exit(1)

    def _questionnaire_basic(self, data, metadata, questionnaire):
        data['schema'] = self.config.MADMP_SCHEMA_URL

        dmp_id = questionnaire['uuid']
        dmp_name = questionnaire['name']
        created_at = questionnaire['createdAt']
        updated_at = questionnaire['updatedAt']
        state = questionnaire.get('state', 'unknown')

        if updated_at:
            data['modified'] = updated_at
        data['title'] = dmp_name
        data['created'] = created_at
        data['dmp_id'] = {
            'identifier': f'{self.config.DSW_PROJECTS_URL}/{dmp_id}',
            'type': 'url',
        }

        if questionnaire['package']:
            package_name = questionnaire['package']['name']
            package_id = questionnaire['package']['id']
            data['description'] = (f'This DMP has been created using Chalmers Data Stewardship Wizard (dsw.chalmers.se) '
                                f'and is based on the knowledge model {package_name} (id: {package_id}).')
            data['language'] = 'swe' if 'swe' in package_id else 'eng'

        metadata['id'] = dmp_id
        if state:
            metadata['state'] = state
        if 'visibility' in questionnaire:
            metadata['visibility'] = questionnaire['visibility']
        if 'sharing' in questionnaire:
            metadata['sharing'] = questionnaire['sharing']
        if 'description' in questionnaire:
            metadata['description'] = questionnaire['description']
        return data, metadata

    def _questionnaire_details(self, data, metadata, questionnaire_full):
        # TODO: this needs more refactoring
        config = self.config.config
        dmp_id = questionnaire_full['uuid']
        data_full = questionnaire_full
        d = data
        md = metadata

        # Disclaimer
        if config.get('Paths', 'disclaimer') in data_full['replies']:
            disclaimer_replies_node = config.get('Paths', 'disclaimer')
            disclaimer_answer = data_full['replies'][disclaimer_replies_node]['value']['value']
            print('disclaimer path: ' + str(disclaimer_answer))
            if disclaimer_answer == config.get('Paths', 'disclaimer_answer_no'):
                print('User has rejected the disclaimer for dmp id: ' + str(dmp_id) + '!')
                md['disclaimer_allow_sharing'] = 'no'
            elif disclaimer_answer == config.get('Paths', 'disclaimer_answer_yes'):
                print('User has approved the disclaimer for dmp id: ' + str(dmp_id) + '!')
                md['disclaimer_allow_sharing'] = 'yes'
            else:
                print('User has not responded to the disclaimer for dmp id: ' + str(dmp_id) + '!')
                md['disclaimer_allow_sharing'] = 'missing / not answered'
        else:
            print('User has not responded to the disclaimer for dmp id: ' + str(dmp_id) + '!')
            md['disclaimer_allow_sharing'] = 'missing / not answered'

        # Contact and contributor(s)
        if config.get('Paths', 'contributors') in data_full['replies']:
            contributors = data_full['replies'][
                config.get('Paths', 'contributors')]

            if contributors:
                cs = []
                cc = {}
                for c in contributors['value']['value']:
                    ct = {}
                    affiliation_node = ''

                    contributor = config.get('Paths', 'contributors') + '.' + c
                    try:
                        name_node = contributor + "." + config.get('Paths', 'contributor.name')
                        contributor_name = data_full['replies'][name_node]['value']['value']
                        ct["name"] = contributor_name
                    except KeyError:
                        contributor_name = ''
                    try:
                        email_node = contributor + "." + config.get('Paths', 'contributor.email')
                        contributor_email = data_full['replies'][email_node]['value']['value']
                        ct["mbox"] = contributor_email
                    except KeyError:
                        contributor_email = ''
                    try:
                        orcid_node = contributor + "." + config.get('Paths', 'contributor.orcid')
                        contributor_orcid = data_full['replies'][orcid_node]['value']['value']
                        ct["contributor_id"] = {"identifier": contributor_orcid, "type": "orcid"}
                    except KeyError:
                        contributor_orcid = ''
                    try:
                        ct["affiliation"] = {}
                        affiliation_node = contributor + '.' + config.get('Paths', 'contributor.affiliation');
                        # print('aff node: ' + affiliation_node)
                        # Non-standard field (CTH), separate field for Horizon Europe KM

                        if affiliation_node + '.' + config.get('Paths', 'contributor.affiliation.cth') in \
                                data_full['replies']:
                            ct["affiliation"] = {"name": "Chalmers University of Technology",
                                                 "affiliation_id": {"name": "https://ror.org/040wg7k59", "type": "ror"}}
                        if affiliation_node in data_full['replies'] and data_full['replies'][affiliation_node]['value'][
                            'value'] == config.get('Paths', 'contributor.affiliation.gu'):
                            ct["affiliation"] = {"name": "University of Gothenburg",
                                                 "affiliation_id": {"name": "https://ror.org/01tm6cn81", "type": "ror"}}
                        if affiliation_node + '.' + config.get('Paths', 'contributor.affiliation.other') in \
                                data_full['replies']:
                            affiliation_other = affiliation_node + '.' + config.get('Paths',
                                                                                    'contributor.affiliation.other')
                            affiliation_other_name = data_full['replies'][affiliation_other]['value']['value']['value']
                            affiliation_other_id = data_full['replies'][affiliation_other]['value']['value']['id']
                            ct["affiliation"] = {"name": affiliation_other_name,
                                                 "affiliation_id": {"name": affiliation_other_id, "type": "ror"}}
                        # HE
                        if 'root-he' in data_full['packageId']:
                            if affiliation_node in data_full['replies']:
                                affiliation_he = affiliation_node
                                affiliation_he_name = data_full['replies'][affiliation_he]['value']['value'][
                                    'value']
                                affiliation_he_id = data_full['replies'][affiliation_he]['value']['value']['id']
                                ct["affiliation"] = {"name": affiliation_he_name,
                                                     "affiliation_id": {"name": affiliation_he_id, "type": "ror"}}
                                print("aff_node_he: " + affiliation_he)
                            # print('aff: ' + contributor_name + ', ' + str(ct['affiliation']))
                    except KeyError:
                        print('no affiliations')
                        ct["affiliation"] = {}
                    try:
                        # default value, todo: multipart roles in HE KM
                        contributor_role = 'contact person'
                        role_node = contributor + "." + config.get('Paths', 'contributor.roles')
                        role_id = data_full['replies'][role_node]['value']['value']
                        print("role: " + str(role_id))

                        if role_id == config.get('Paths', 'contributor.role.contact'):
                            contributor_role = 'contact person'
                            if contributor_orcid:
                                cc['contact_id'] = {"identifier": contributor_orcid, "type": "orcid"}
                            cc['affiliation'] = ct['affiliation']
                            cc['name'] = contributor_name
                            if contributor_email:
                                cc['mbox'] = contributor_email
                        elif role_id == config.get('Paths', 'contributor.role.datacollector'):
                            contributor_role = 'data collector'
                        elif role_id == config.get('Paths', 'contributor.role.datacurator'):
                            contributor_role = 'data curator'
                        elif role_id == config.get('Paths', 'contributor.role.datasteward'):
                            contributor_role = 'data steward'
                        elif role_id == config.get('Paths', 'contributor.role.researcher'):
                            contributor_role = 'researcher'
                        elif role_id == config.get('Paths', 'contributor.role.other'):
                            contributor_role = 'other'
                        # HE
                        if config.get('Paths', 'contributor.role_he.contact') in role_id:
                            cc = {}
                            contributor_role = 'contact person'
                            if contributor_orcid:
                                cc['contact_id'] = {"identifier": contributor_orcid, "type": "orcid"}
                            cc['affiliation'] = ct['affiliation']
                            cc['name'] = contributor_name
                            if contributor_email:
                                cc['mbox'] = contributor_email
                        # else:
                        #    contributor_role = 'other'
                    except KeyError:
                        contributor_role = '(unknown)'
                    ct["role"] = [contributor_role]

                    cs.append(ct)

            d["contributor"] = cs
            if cc:
                d["contact"] = cc
                md['hasContactPerson'] = 'true'
            else:
                md['hasContactPerson'] = 'false'

        # Projects and funding

        md['hasProject'] = 'false'

        if config.get('Paths', 'projects') in data_full['replies']:
            projects = data_full['replies'][config.get('Paths', 'projects')]

            if projects:
                ps = []
                md['hasProject'] = 'true'
                for p in projects['value']['value']:
                    pt = {}
                    project = config.get('Paths', 'projects') + '.' + p
                    try:
                        pname_node = project + "." + config.get('Paths', 'project.name')
                        pname = data_full['replies'][pname_node]['value']['value']
                        pt["title"] = pname
                    except KeyError:
                        pname = ''
                    try:
                        pdesc_node = project + "." + config.get('Paths', 'project.desc')
                        pdesc = data_full['replies'][pdesc_node]['value']['value']
                        pdesc = pdesc.replace('\n', ' ')
                        pt["description"] = pdesc
                    except KeyError:
                        pdesc = ''
                    try:
                        pacronym_node = project + "." + config.get('Paths', 'project.acronym')
                        pacronym = data_full['replies'][pacronym_node]['value']['value']
                        pt["acronym"] = pacronym
                    except KeyError:
                        pacronym = ''
                    try:
                        pstart_node = project + "." + config.get('Paths', 'project.start')
                        pstart = data_full['replies'][pstart_node]['value']['value']
                        # Modify date format if necessary
                        if len(pstart) > 10:
                            pstart = pstart[0:10]
                        pt["start"] = pstart
                    except KeyError:
                        pstart = ''
                    try:
                        pend_node = project + "." + config.get('Paths', 'project.end')
                        pend = data_full['replies'][pend_node]['value']['value']
                        # Modify date format if necessary
                        if len(pend) > 10:
                            pend = pend[0:10]
                        pt["end"] = pend
                    except KeyError:
                        pend = ''
                    try:
                        pfunding_node = project + "." + config.get('Paths', 'project.funding')
                        pfl = []
                        for pf in data_full['replies'][pfunding_node]['value']['value']:
                            pfn = {}
                            funding = pfunding_node + '.' + pf
                            # print('funding: ' + funding)
                            try:
                                pf_funder_node = funding + "." + config.get('Paths', 'project.funder')
                                pf_funder = data_full['replies'][pf_funder_node]['value']['value']['id']
                                pf_funder_name = data_full['replies'][pf_funder_node]['value']['value']['value']
                                pfn['funder_name'] = pf_funder_name
                                if pf_funder_name == 'Vetenskapsrådet':
                                    pfn['funder_id'] = {'identifier': 'https://ror.org/03zttf063', 'type': 'other'}
                                else:
                                    pfn['funder_id'] = {'identifier': pf_funder, 'type': 'url'}
                            except KeyError:
                                pfunder = ''
                            try:
                                pf_grant_node = funding + "." + config.get('Paths', 'project.funder.grant')
                                pf_grant = data_full['replies'][pf_grant_node]['value']['value']
                                pfn['grant_id'] = {'identifier': pf_grant, 'type': 'other'}
                            except KeyError:
                                pfunder = ''
                            try:
                                pf_status_node = funding + "." + config.get('Paths', 'project.funding.status')
                                pf_status_id = data_full['replies'][pf_status_node]['value']['value']
                                if pf_status_id == config.get('Paths', 'project.funding.status.granted'):
                                    pf_status = 'granted'
                                elif pf_status_id == config.get('Paths', 'project.funding.status.applied'):
                                    pf_status = 'applied'
                                elif pf_status_id == config.get('Paths', 'project.funding.status.planned'):
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
        if config.get('Paths', 'ethical_issues') in data_full['replies']:
            if \
                    data_full['replies'][config.get('Paths', 'ethical_issues')][
                        'value']['value'] == config.get('Paths', 'ethical_issues.yes'):
                ethical_issues_exist = 'yes'
                md['hasPersonalData'] = 'true'
                if config.get('Paths', 'ethical_issues.desc') in \
                        data_full['replies']:
                    ethical_issues_desc = data_full['replies'][
                        config.get('Paths', 'ethical_issues.desc')][
                        'value']['value']
                    d['ethical_issues_description'] = ethical_issues_desc
            if \
                    data_full['replies'][config.get('Paths', 'ethical_issues')][
                        'value'][
                        'value'] == config.get('Paths', 'ethical_issues.no'):
                ethical_issues_exist = 'yes'
                ethical_issues_exist = 'no'

        d['ethical_issues_exist'] = ethical_issues_exist

        # GDPR (Horizon Europe KM)
        if config.get('Paths', 'ethical_issues_he') in data_full['replies']:
            if \
                    data_full['replies'][config.get('Paths', 'ethical_issues_he')][
                        'value']['value'] == config.get('Paths', 'ethical_issues_he.yes'):
                ethical_issues_exist = 'yes'
                md['hasPersonalData'] = 'true'
                if config.get('Paths', 'ethical_issues_he.desc') in \
                        data_full['replies']:
                    ethical_issues_desc = data_full['replies'][
                        config.get('Paths', 'ethical_issues_he.desc')][
                        'value']['value']
                    d['ethical_issues_description'] = ethical_issues_desc
            if \
                    data_full['replies'][config.get('Paths', 'ethical_issues_he')][
                        'value'][
                        'value'] == config.get('Paths', 'ethical_issues_he.no'):
                ethical_issues_exist = 'no'
                ethical_issues_exist = 'no'

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
                    dset["dataset_id"] = {'identifier': str(uuid.uuid4()), 'type': 'other'}
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
                        d['dataset'] = dsts
                        print('dataset added')
        else:
            print('NO DATASETS')
            # Create a generic (empty) set to comply with standard
            md['hasDatasets'] = 'false'
            dsts_empty = []
            dset_empty = {"type": 'dataset', "title": 'Generic dataset',
                          "description": 'No individual datasets have been defined for this DMP.',
                          "dataset_id": {'identifier': str(uuid.uuid4()), 'type': 'other'}, "sensitive_data": 'unknown',
                          "personal_data": 'unknown'}
            dsts_empty.append(dset_empty)
            d['dataset'] = dsts_empty
            print('generic (dummy) dataset added')

        # Additional metadata (local)

        md['indexed'] = datetime.datetime.now().strftime('%Y-%m-%dT%H:%M:%SZ')

        # DMP owner (for now eq to (first named) admin)
        md['dmp_owner'] = {}
        for op in data_full['permissions']:
            # print(op)
            if 'ADMIN' in op['perms']:
                owner_name = op['member']['firstName'] + ' ' + op['member']['lastName']
                owner_uuid = op['member']['uuid']
                md['dmp_owner'] = {'name': owner_name, 'uuid': owner_uuid}
                break

        md['hasExistingData'] = 'false'
        if '82fd0cce-2b41-423f-92ad-636d0872045c.efc80cc8-8318-4f8c-acb7-dc1c60e491c1' in data_full['replies']:
            if \
                    data_full['replies']['82fd0cce-2b41-423f-92ad-636d0872045c.efc80cc8-8318-4f8c-acb7-dc1c60e491c1'][
                        'value'][
                        'value'] == '2663b978-5125-4224-9930-0a50dbe895c9':
                md['hasExistingData'] = 'true'

        md['hasCollectingNewData'] = 'false'
        if 'b1df3c74-0b1f-4574-81c4-4cc2d780c1af.f87c331d-794a-42c8-a910-61a2a9110dab' in data_full['replies']:
            if \
                    data_full['replies']['b1df3c74-0b1f-4574-81c4-4cc2d780c1af.f87c331d-794a-42c8-a910-61a2a9110dab'][
                        'value'][
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

        if config.get('Paths', 'metadata.storage_needs') in data_full['replies']:
            storage_needs_id = \
                data_full['replies'][config.get('Paths', 'metadata.storage_needs')][
                    'value'][
                    'value']
            if storage_needs_id == config.get('Paths', 'metadata.storage_needs.very_small'):
                storage_needs = 'Very small, < 1 TB'
            elif storage_needs_id == config.get('Paths', 'metadata.storage_needs.small'):
                storage_needs = 'Small (1-5 TB)'
            elif storage_needs_id == config.get('Paths', 'metadata.storage_needs.large'):
                storage_needs = 'Large (5-50 TB)'
            elif storage_needs_id == config.get('Paths', 'metadata.storage_needs.very_large'):
                storage_needs = 'Very large (>= 50 TB)'
            else:
                storage_needs = 'unknown'
            md['storage_needs'] = storage_needs

        if 'root-he' in data_full['packageId']:
            if config.get('Paths', 'metadata.storage_needs_he') in data_full['replies']:
                storage_needs_id = \
                    data_full['replies'][config.get('Paths', 'metadata.storage_needs_he')][
                        'value'][
                        'value']
                if storage_needs_id == config.get('Paths', 'metadata.storage_needs.very_small_he'):
                    storage_needs = 'Very small, < 1 TB'
                elif storage_needs_id == config.get('Paths', 'metadata.storage_needs.small_he'):
                    storage_needs = 'Small (1-5 TB)'
                elif storage_needs_id == config.get('Paths', 'metadata.storage_needs.large_he'):
                    storage_needs = 'Large (5-50 TB)'
                elif storage_needs_id == config.get('Paths', 'metadata.storage_needs.very_large_he'):
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


if __name__ == '__main__':
    dotenv.load_dotenv()

    config = Config()
    dsw2es = DSW2ES(config)
    dsw2es.run()
