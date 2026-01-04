import stix2
from datetime import datetime, timezone
from stix2 import properties, CustomObject
from pycti import (
    AttackPattern,
    Identity,
    Incident,
    Indicator,
    Note,
    StixCoreRelationship,
)


@CustomObject(
    'hostname',
    [('value', properties.StringProperty(required=True))]
)
class _Hostname(object):
    pass


class ConverterToStix:

    def __init__(self, helper, s1_client=None):
        self.helper = helper
        self.s1_client = s1_client
        self.current_author = None

    def _get_or_create_author(self, s1_incident: dict) -> stix2.Identity:
        """
        Gets or creates the site organization as author from incident data
        """
        orgname = s1_incident.get("agentRealtimeInfo", {}).get("siteName", "unknown")
        author = stix2.Identity(
            id=Identity.generate_id(
                name=orgname, identity_class="organization"
            ),
            name=orgname,
            identity_class="organization",
            description="Site as Organization",
        )
        self.current_author = author
        return author

    def create_incident(
        self, incident_data: dict, incident_id: str, s1_url: str
    ) -> list[stix2.Incident]:
        """
        Creates a Stix Incident from a SentinelOne incident alongside
        an external reference with a link to accessing it.
        """
        self.helper.connector_logger.debug(
            "Attempting to create corresponding Stix Incident"
        )

        machine = incident_data.get("agentRealtimeInfo", {}).get(
            "agentComputerName", "unknown"
        )
        account_name = incident_data.get("agentRealtimeInfo", {}).get(
            "accountName", "unknown"
        )
        account_id = incident_data.get("agentRealtimeInfo", {}).get(
            "accountId", "unknown"
        )
        description = (
            f"Threat detected on machine {machine} under account {account_name} (id: {account_id})."
            f"\nThreat Name: {incident_data['threatInfo']['threatName']}."
            f"\nMitigation Status: {incident_data['threatInfo']['mitigationStatusDescription']}."
        )
        labels = [
            indicator.get("category", "")
            for indicator in incident_data.get("indicators", [])
            if indicator.get("category", "") != ""
        ]

        external_s1_ref = stix2.ExternalReference(
            source_name="SentinelOne",
            url=f"{s1_url}/incidents/threats/{incident_id}/overview",
            description="View Incident In SentinelOne",
            external_id=incident_id,
        )

        author = self._get_or_create_author(incident_data)

        name = incident_data.get("threatInfo", {}).get("threatName", "")
        created = incident_data.get("threatInfo", {}).get("identifiedAt", "")

        incident = stix2.Incident(
            id=Incident.generate_id(name, created),
            created_by_ref=author,
            type="incident",
            name=name,
            description=description,
            labels=labels,
            created=created,
            external_references=[external_s1_ref] if external_s1_ref else None,
            object_marking_refs=[stix2.TLP_RED.id],
            custom_properties={"source": author.name},
        )

        return [incident]

    def create_organization_observables(
        self, s1_incident: dict, cti_incident_id: str
    ) -> list:
        """
        Returns the site organization (author) as an observable with relationship to incident
        """
        self.helper.connector_logger.debug(
            "Returning organization observable"
        )
        
        if not self.current_author:
            self.helper.connector_logger.warning("No author set, skipping organization observable")
            return []
        
        org_relationship = self.create_relationship(
            cti_incident_id, self.current_author["id"], "related-to"
        )
        
        return [self.current_author, org_relationship]

    def create_endpoint_observable(
        self, s1_incident: dict, cti_incident_id: str
    ) -> list[stix2.UserAccount, stix2.Relationship]:
        """
        Creates a Stix UserAccount Observable from a SentinelOne incident
        alongside a relationship to the incident.
        """

        self.helper.connector_logger.debug(
            "Attempting to create Endpoint Observable"
        )

        endpoint_name = s1_incident.get("agentRealtimeInfo", {}).get(
            "agentComputerName", ""
        )
        if not endpoint_name:
            return []

        account_name = s1_incident.get("agentRealtimeInfo", {}).get(
            "accountName", "unknown"
        )
        account_id = s1_incident.get("agentRealtimeInfo", {}).get(
            "accountId", "unknown"
        )
        desc = f"Affected Host on SentinelOne Account {account_name} (with id: {account_id})"

        endpoint_observable = _Hostname(
            value=endpoint_name,
            object_marking_refs=[stix2.TLP_RED.id],
            custom_properties={"description": desc},
        )

        endpoint_relationship = self.create_relationship(
             cti_incident_id, endpoint_observable["id"], "related-to"
        )

        return [endpoint_observable, endpoint_relationship]

    def create_user_account_observables(
        self, s1_incident: dict, cti_incident_id: str
    ) -> list[stix2.UserAccount, stix2.Relationship]:
        """
        Creates a Stix UserAccount Observable from a SentinelOne incident
        alongside a relationship to the incident.
        """

        self.helper.connector_logger.debug(
            "Attempting to create User Observable"
        )

        user_name = s1_incident.get("agentDetectionInfo", {}).get(
            "agentLastLoggedInUpn", ""
        )
        if not user_name:
            return []

        account_name = s1_incident.get("agentRealtimeInfo", {}).get(
            "accountName", "unknown"
        )
        account_id = s1_incident.get("agentRealtimeInfo", {}).get(
            "accountId", "unknown"
        )

        if s1_incident.get("agentRealtimeInfo", {}).get("agentOsType", "") == "Windows":
            if s1_incident.get("agentRealtimeInfo", {}).get("agentDomain", "") != "":
                user_type = "windows-domain"
            else:
                user_type = "windows-local"
        else:
            user_type = "unix"
            

        desc = f"Affected user on SentinelOne Account {account_name} (with id: {account_id})"

        endpoint_observable = stix2.UserAccount(
            account_type=user_type,
            user_id=user_name,
            object_marking_refs=[stix2.TLP_RED.id],
            custom_properties={"description": desc},
        )

        endpoint_relationship = self.create_relationship(
             cti_incident_id, endpoint_observable["id"], "related-to"
        )

        return [endpoint_observable, endpoint_relationship]

    def create_attack_patterns(self, incident_data: dict, cti_incident_id: str) -> list:
        """
        Creates a Stix Attack Pattern from a SentinelOne incident
        alongside a relationship to the incident.
        """

        def create_mitre_reference(technique):
            mitre_ref = stix2.ExternalReference(
                source_name="MITRE ATT&CK",
                url=technique.get("link"),
                external_id=technique.get("name"),
            )
            return mitre_ref

        self.helper.connector_logger.debug("Attempting to create Stix Attack Patterns")

        attack_patterns = []

        for pattern in incident_data.get("indicators", []):
            pattern_name = (
                pattern.get("category", "")
                + ": "
                + ", ".join(
                    [
                        tactic.get("name", "")
                        for tactic in pattern.get("tactics", [])
                        if tactic.get("name", "") != ""
                    ]
                )
            )

            attack_pattern = stix2.AttackPattern(
                id=AttackPattern.generate_id(pattern_name),
                created_by_ref=self.current_author,
                name=pattern_name,
                description=pattern.get("description", ""),
                object_marking_refs=[stix2.TLP_RED.id],
            )

            for tactic in pattern.get("tactics", []):
                sub_desc = ", ".join(
                    [
                        technique.get("name", "")
                        for technique in tactic.get("techniques", [])
                        if technique.get("name", "") != ""
                    ]
                )

                sub_name = "[sub] " + tactic.get("name", "")
                sub_pattern = stix2.AttackPattern(
                    id=AttackPattern.generate_id(sub_name),
                    created_by_ref=self.current_author,
                    name=sub_name,
                    description=sub_desc,
                    external_references=[
                        create_mitre_reference(technique)
                        for technique in tactic.get("techniques", [])
                    ],
                    object_marking_refs=[stix2.TLP_RED.id],
                )

                attack_patterns.append(sub_pattern)
                attack_patterns.append(
                    self.create_relationship(cti_incident_id, sub_pattern["id"], "uses")
                )

            attack_patterns.append(attack_pattern)
            attack_patterns.append(
                self.create_relationship(cti_incident_id, attack_pattern["id"], "uses")
            )

        return attack_patterns

    def create_notes(self, s1_notes: list, cti_incident_id: str) -> list:
        """
        Creates a Stix Note from a SentinelOne incident
        alongside a relationship to the incident.
        """

        self.helper.connector_logger.debug("Attempting to create Stix Notes")

        incident_notes = []
        for note in s1_notes:
            # Convert None values to empty strings before concatenation
            note_text = str(note.get("text", "") or "")
            note_creator = str(note.get("creator", "") or "")
            content = note_text + "\ncreated by: " + note_creator
            created = note.get("createdAt", "")
            incident_note = stix2.Note(
                id=Note.generate_id(content=content, created=created),
                created_by_ref=self.current_author,
                content=content,
                object_refs=[cti_incident_id],
                object_marking_refs=[stix2.TLP_RED.id],
            )
            incident_notes.append(incident_note)

        return incident_notes

    def create_file_observables(self, s1_incident: dict, cti_incident_id: str) -> list:
        """
        Creates a Stix File Observable wrapped in ObservedData from a SentinelOne incident
        alongside a relationship to the incident.
        """

        self.helper.connector_logger.debug("Attempting to create File Observables")

        threat_info = s1_incident.get("threatInfo", {})

        sha1 = threat_info.get("sha1", "")
        sha256 = threat_info.get("sha256", "")
        observables = []
        hashes = {}
        if sha256:
            hashes["SHA-256"] = sha256
        if sha1:
            hashes["SHA-1"] = sha1
        if not hashes:
            return []
        
        self.helper.connector_logger.info("Creating Stix Observable with hashes: " + str(hashes))
        
        file_observable = stix2.File(
            type="file",
            name=threat_info.get("threatName", ""),
            hashes=hashes,
            object_marking_refs=[stix2.TLP_RED],
        )
        
        observables.append(file_observable)
        observables.append(
            self.create_relationship(cti_incident_id, file_observable["id"], "uses")
        )
        
        return observables

    def get_ipv4_observable(self, s1_incident: dict, cti_incident_id: str) -> list:
        events = self.s1_client.fetch_related_ips(s1_incident.get("threatInfo", {}).get("threatId"))
        observables = []
        if not events:
            return []
        if len(events) == 0:
            return []
        for event in events:
            ip=event.get("dstIp", "")
            observable = stix2.IPv4Address(
                value=ip,
                object_marking_refs=[stix2.TLP_RED],
            )
            observables.append(observable)
            observables.append(
                self.create_relationship(cti_incident_id, observable["id"], "related-to")
            )
            
        return observables

    def get_domain_observable(self, s1_incident: dict, cti_incident_id: str) -> list:
        events = self.s1_client.fetch_related_domains(s1_incident.get("threatInfo", {}).get("threatId"))
        observables = []
        if not events:
            return []
        if len(events) == 0:
            return []
        for event in events:
            domain=event.get("dnsRequest", "")
            observable = stix2.DomainName(
                value=domain,
                object_marking_refs=[stix2.TLP_RED],
            )
            observables.append(observable)
            observables.append(
                self.create_relationship(cti_incident_id, observable["id"], "related-to")
            )
            
        return observables

    def bundle_observed_data(self, cti_incident_id: str, stix_objects: list) -> list:
        # Filter to only include SCOs (observables) and SROs (relationships)
        # Exclude SDOs like incident, attack-pattern, note, identity
        excluded_sdo_types = ['incident', 'attack-pattern', 'note', 'identity', 'observed-data']
        filtered_stix_objects = [
            obj['id'] for obj in stix_objects 
            if hasattr(obj, 'get') and obj.get('type') not in excluded_sdo_types
        ]
        
        if not filtered_stix_objects:
            self.helper.connector_logger.info("No SCOs/SROs found to bundle in ObservedData")
            return []
        
        now = datetime.now(timezone.utc)
        data = stix2.ObservedData(
            first_observed=now,
            last_observed=now,
            number_observed=len(filtered_stix_objects),
            created_by_ref=self.current_author,
            object_refs=filtered_stix_objects,
            object_marking_refs=[stix2.TLP_RED.id],
        )
        
        relationship = self.create_relationship(cti_incident_id, data["id"], "related-to")
        
        return [data, relationship]                

    def create_relationship(
        self, parent_id: str, child_id: str, relationship_type: str
    ) -> stix2.Relationship:
        """
        Creates a Stix Relationship between two objects
        """
        relationship = stix2.Relationship(
            id=StixCoreRelationship.generate_id(relationship_type, parent_id, child_id),
            created_by_ref=self.current_author,
            relationship_type=relationship_type,
            source_ref=parent_id,
            target_ref=child_id,
            object_marking_refs=[stix2.TLP_RED.id],
        )
        return relationship
