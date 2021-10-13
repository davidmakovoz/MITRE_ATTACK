CALL apoc.load.csv("file://enterprise-attack-v9.0-tactics.csv") yield map as row 
MERGE (t:Tactic {ID:row.ID})
ON CREATE set t.name = row.name, t.description = row.description, t.url = row.url,	t.created = row.created, t.last_modified = row.last_modified


CALL apoc.load.csv("file://enterprise-attack-v9.0-maintechniques.csv") yield map as row 
MERGE (t:Technique {ID:row.mID})
ON CREATE set t.name = row.name, t.description = row.description, t.url = row.url,	t.created = row.created, t.last_modified = row.last_modified, t.version = row.version

CALL apoc.load.csv("file://enterprise-attack-v9.0-subtechniques.csv") yield map as row 
MERGE (t:SubTechnique {ID:row.ID})
ON CREATE set t.name = row.sub_name, t.super_name = row.super_name, t.description = row.description, t.url = row.url,	t.created = row.created, t.last_modified = row.last_modified, t.version = row.version, t.SuperID = row.mID, t.subID = row.subID

CALL apoc.load.csv("file://enterprise-attack-v9.0-subtechniques.csv") yield map as row 
MATCH (st:SubTechnique {ID:row.ID})
MATCH (t:Technique {ID:row.mID}) 
MERGE (st)-[:IS_SUB_TECHNIQUE]->(t)

CALL apoc.load.csv("file://enterprise-attack-v9.0-datasources.csv") yield map as row 
MERGE (d:DataSourceType {name:row.data_source_type})
MERGE (ds:DataSource {name:row.data_source})

CALL apoc.load.csv("file://enterprise-attack-v9.0-datasources.csv") yield map as row 
MATCH (d:DataSourceType {name:row.data_source_type})
MATCH (ds:DataSource {name:row.data_source}) with d, ds
MERGE (ds)-[:HAS_TYPE]->(d)


CALL apoc.load.csv("file://enterprise-attack-v9.0-maintechniques.csv") yield map as row 
with SPLIT(row.tactics, ',') as tactics, row  unwind tactics as tac with tac, row
match (tt:Technique {ID:row.ID})
match (t:Tactic {name:trim(tac)}) 
MERGE (tt)-[:PART_OF_TACTIC]->(t)

CALL apoc.load.csv("file://enterprise-attack-v9.0-subtechniques.csv") yield map as row 
with SPLIT(row.data_sources, ',') as data_sources, row unwind data_sources as data_source with data_source, row where not data_source = "" 
with TRIM(SPLIT(data_source, ': ')[1]) as dss, row
MATCH (st:SubTechnique {ID:row.ID})
MATCH (ds:DataSource {name:dss})
MERGE (st)-[:HAS_DATA_SOURCE]->(ds)


CALL apoc.load.csv("file://enterprise-attack-v9.0-maintechniques.csv") yield map as row 
with SPLIT(row.data_sources, ',') as data_sources, row unwind data_sources as data_source with data_source, row where not data_source = "" 
with TRIM(SPLIT(data_source, ': ')[1]) as dss, row
MATCH (t:Technique {ID:row.ID}) 
MATCH (ds:DataSource {name:dss})
where not (t)<-[:IS_SUB_TECHNIQUE]-(:SubTechnique) with t, ds
MERGE (t)-[:HAS_DATA_SOURCE]->(ds)

### SOFTWARE
CALL apoc.load.csv("file://enterprise-attack-v9.0-software.csv") yield map as row 
MERGE (s:Software {ID:row.ID})
ON CREATE set s.name = row.name, s.description = row.description, s.url = row.url,	s.created = row.created, s.last_modified = row.last_modified, s.last_modified = row.last_modified, s.version  = row.version
Added 493 labels, created 493 nodes, set 2958 properties, completed after 685 ms.

CALL apoc.load.csv("file://enterprise-attack-v9.0-software.csv") yield map as row where not row.platforms = "" 
with SPLIT(row.platforms, ',') as platforms, row  unwind platforms as plat with plat, row
match (s:Software {ID:row.ID})
MERGE (p:Platform {name:trim(plat)}) 
MERGE (s)-[:DEPLOYED_ON_PLATFORM]->(p)
Added 9 labels, created 9 nodes, set 552 properties, created 552 relationships, completed after 620 ms.

CALL apoc.load.csv("file://enterprise-attack-v9.0-software.csv") yield map as row where not row.platforms = "" 
with SPLIT(row.platforms, ',') as platforms, row  
match (s:Software {ID:row.ID})
set s.platforms = platforms
Set 488 properties, completed after 215 ms.

CALL apoc.load.csv("file://enterprise-attack-v9.0-software.csv") yield map as row where not row.aliases = "" 
with SPLIT(row.aliases, ',') as aliases , row
match (s:Software {ID:row.ID})
SET s.aliases = aliases
Set 123 properties, completed after 87 ms.

### GROUPS
CALL apoc.load.csv("file://enterprise-attack-v9.0-groups.csv") yield map as row 
MERGE (g:Group {ID:row.ID})
ON CREATE set g.name = row.name, g.description = row.description, g.url = row.url,	g.created = row.created, g.last_modified = row.last_modified, g.last_modified = row.last_modified, g.version  = row.version
Added 121 labels, created 121 nodes, set 726 properties, completed after 43 ms.

CALL apoc.load.csv("file://enterprise-attack-v9.0-groups.csv") yield map as row where not row.associated_groups = "" 
with SPLIT(row.associated_groups, ',') as associated_groups, row  unwind associated_groups as agroups with agroups, row
match (g:Group {ID:row.ID})
MERGE (ag:Group {name:trim(agroups)}) 
MERGE (g)<-[:ASSOIATED_WITH]-(ag)
Added 188 labels, created 188 nodes, set 188 properties, created 189 relationships, completed after 97 ms.

CALL apoc.load.csv("file://enterprise-attack-v9.0-groups.csv") yield map as row where not row.associated_groups = "" 
with SPLIT(row.associated_groups, ',') as associated_groups, row  
match (g:Group {ID:row.ID})
SET g.associated_groups = associated_groups
Set 63 properties, completed after 52 ms.

### MITIGATIONs
CALL apoc.load.csv("file://enterprise-attack-v9.0-mitigations.csv") yield map as row 
MERGE (m:Mitigation {ID:row.ID})
ON CREATE set m.name = row.name, m.description = row.description, m.url = row.url,	m.created = row.created, m.last_modified = row.last_modified, m.last_modified = row.last_modified, m.version  = row.version
Added 42 labels, created 42 nodes, set 252 properties, completed after 15 ms.


#################RELATIONSHIPs
##source_ID	source_name	source_type	mapping_type	target_ID	target_name	target_type	mapping_description
CALL apoc.load.csv("file://enterprise-attack-v9.0-relationships.csv") yield map as row where row.mapping_type = "MITIGATES"
match (s {ID:row.source_ID}) 
match (t {ID:row.target_ID}) 
MERGE (s)-[:MITIGATES {description:row.mapping_description}]->(t)
Set 1026 properties, created 1026 relationships, completed after 6193 ms.

CALL apoc.load.csv("file://enterprise-attack-v9.0-relationships.csv") yield map as row where row.mapping_type = "USES"
match (s {ID:row.source_ID}) 
match (t {ID:row.target_ID}) 
MERGE (s)-[:USES {description:row.mapping_description}]->(t)
Set 7052 properties, created 7052 relationships, completed after 17305 ms.

CALL apoc.load.csv("file://enterprise-attack-v9.0-relationships.csv") yield map as row 
match (s {name:row.source_name})  where not s.ID = row.source_ID return row there are different entities with the same name, e.g. Software and Group "Carbanak"

match (s {ID:row.source_ID, name:row.source_name}) return count(s) //8078
match (s {name:row.source_name}) return count(s) //8235 there are different entities with the same name, e.g. Software and Group "Carbanak"
match (s {ID:row.source_ID}) return count(s) //8078

CALL apoc.load.csv("file://enterprise-attack-v9.0-relationships.csv") yield map as row 
match (t {name:row.target_name, ID:row.target_ID}) return count(t) //3942
match (t {name:row.target_name}) return count(t) //4132
match (t {ID:row.target_ID}) return count(t) //8078

source ID	source name	source type	mapping type	target ID	target name	target type	mapping description

############################################################################3


with TRIM(SPLIT(data_source, ':')[0]) as dst, TRIM(SPLIT(data_source, ': ')[1]) as dss
return dst, dss

 t.system_requirements = row.system_requirements, t.permissions_required = ow.permissions_required, t.effective_permissions = row.effective_permissions, t.defenses_bypassed = row.defenses_bypassed, t.impact_type = row.impact_type


'ID', 'name', 'description', 'url', 'created', 'last_modified',
       'version', 'tactics', 'detection', 'platforms', 'data_sources',
       'is_sub_technique', 'sub_technique_of', 'contributors',
       'system_requirements', 'permissions_required', 'effective_permissions',
       'defenses_bypassed', 'impact_type', 'supports_remote', 'mID', 'subID'

ON CREATE set t.name = row.name, t.description = row.description, t.url = row.url,	t.created = date(row.created), t.last_modified = date(row.last_modified)
