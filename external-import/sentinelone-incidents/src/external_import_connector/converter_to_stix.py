import stix2
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
        self.author = self._create_author()

    def _create_author(self) -> dict:
        """
        Creates an author for the connector
        """
        author = stix2.Identity(
            id=Identity.generate_id(
                name="SentinelOne", identity_class="organization"
            ),
            name="SentinelOne",
            identity_class="organization",
            description="The SentinelOne Connector",
        )
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
        orgname = incident_data.get("agentRealtimeInfo", {}).get(
            "siteName", "unknown"
        )
        author = stix2.Identity(
            id=Identity.generate_id(
                name=orgname, identity_class="organization"
            ),
            name=orgname,
            identity_class="organization",
            description="The SentinelOne Connector",
        )

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
                created_by_ref=self.author,
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
                    created_by_ref=self.author,
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
                created_by_ref=self.author,
                content=content,
                object_refs=[cti_incident_id],
                object_marking_refs=[stix2.TLP_RED.id],
            )
            incident_notes.append(incident_note)

        return incident_notes

    def create_file_observables(self, s1_incident: dict, cti_incident_id: str) -> list:
        """
        Creates a Stix Observable from a SentinelOne incident
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
        observable = stix2.File(
                type="file",
                name=threat_info.get("threatName", ""),
                hashes=hashes,
                object_marking_refs=[stix2.TLP_RED],
                )
        observables.append(
            self.create_relationship(cti_incident_id, observable["id"], "related-to")
        )
        observables.append(observable)
        observables.append(self.create_ip_observables(s1_incident, observable["id"]))
        return observables

    def create_ip_observables(self, s1_incident: dict, observable_id: str) -> list:
        self.helper.connector_logger.debug("Attempting to create File Observables")

        threat_info = s1_incident.get("threatInfo", {})

        sha1 = threat_info.get("sha1", "")
        endpoint_name = s1_incident.get("agentComputerName", "")
        observables = []
        if not sha1:
            return []
        
        result = self.s1_client.fetch_related_ips(sha1, endpoint_name)
        ips = []
        for item in result:
            ips.append(item[0])
        
        if not ips:
            return []
        
        self.helper.connector_logger.info("Creating Stix Observable with IPs: " + str(len(ips)))
        for ip in ips:
            observable = stix2.IPv4Address(
                value=ip,
                object_marking_refs=[stix2.TLP_RED],
                )
            observables.append(
                self.create_relationship(observable_id, observable["id"], "related-to")
            )
            observables.append(observable)

        return observables

    def create_relationship(
        self, parent_id: str, child_id: str, relationship_type: str
    ) -> stix2.Relationship:
        """
        Creates a Stix Relationship between two objects
        """
        relationship = stix2.Relationship(
            id=StixCoreRelationship.generate_id(relationship_type, parent_id, child_id),
            created_by_ref=self.author,
            relationship_type=relationship_type,
            source_ref=parent_id,
            target_ref=child_id,
            object_marking_refs=[stix2.TLP_RED.id],
        )
        return relationship
