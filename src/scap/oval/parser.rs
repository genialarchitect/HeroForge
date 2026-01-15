//! OVAL Parser
//!
//! Parses OVAL XML content (definitions, tests, objects, states, variables).

use anyhow::{Result, bail};
use quick_xml::events::{Event, BytesStart};
use quick_xml::reader::Reader;

use super::types::*;
use super::OvalDefinitions;

/// Parser for OVAL XML content
pub struct OvalParser;

impl OvalParser {
    /// Parse OVAL definitions from XML
    pub fn parse(xml: &str) -> Result<OvalDefinitions> {
        let mut reader = Reader::from_str(xml);
        reader.config_mut().trim_text(true);

        let mut definitions = OvalDefinitions::new();
        let mut buf = Vec::new();
        let mut current_path: Vec<String> = Vec::new();
        let mut current_text = String::new();

        // Current parsing state
        let mut current_definition: Option<OvalDefinition> = None;
        let mut current_test: Option<OvalTest> = None;
        let mut current_object: Option<OvalObject> = None;
        let mut current_state: Option<OvalState> = None;
        let mut current_variable: Option<OvalVariable> = None;
        let mut current_criteria: Option<Criteria> = None;
        let mut criteria_stack: Vec<Criteria> = Vec::new();

        loop {
            match reader.read_event_into(&mut buf) {
                Ok(Event::Start(ref e)) => {
                    let name = Self::local_name(e);
                    current_path.push(name.clone());

                    match name.as_str() {
                        "definition" => {
                            current_definition = Some(Self::parse_definition_start(e)?);
                        }
                        "criteria" => {
                            let criteria = Self::parse_criteria_start(e)?;
                            if current_criteria.is_some() {
                                criteria_stack.push(current_criteria.take().unwrap());
                            }
                            current_criteria = Some(criteria);
                        }
                        "criterion" => {
                            if let Some(ref mut criteria) = current_criteria {
                                let c = Self::parse_criterion(e)?;
                                criteria.children.push(CriteriaNode::Criterion(c));
                            }
                        }
                        "extend_definition" => {
                            if let Some(ref mut criteria) = current_criteria {
                                let def_ref = Self::get_attr(e, "definition_ref")?;
                                criteria.children.push(CriteriaNode::ExtendDefinition(def_ref));
                            }
                        }
                        _ if name.ends_with("_test") => {
                            current_test = Some(Self::parse_test_start(e)?);
                        }
                        _ if name.ends_with("_object") => {
                            current_object = Some(Self::parse_object_start(e, &name)?);
                        }
                        _ if name.ends_with("_state") => {
                            current_state = Some(Self::parse_state_start(e, &name)?);
                        }
                        "local_variable" | "constant_variable" | "external_variable" => {
                            current_variable = Some(Self::parse_variable_start(e, &name)?);
                        }
                        _ => {}
                    }
                }
                Ok(Event::End(ref e)) => {
                    let name = Self::local_name_end(e);

                    match name.as_str() {
                        "definition" => {
                            if let Some(mut def) = current_definition.take() {
                                def.criteria = current_criteria.take();
                                definitions.definitions.insert(def.id.clone(), def);
                            }
                        }
                        "criteria" => {
                            if let Some(parent) = criteria_stack.pop() {
                                // Add current criteria as nested to parent
                                let child = current_criteria.take().unwrap();
                                current_criteria = Some(parent);
                                if let Some(ref mut c) = current_criteria {
                                    c.children.push(CriteriaNode::Criteria(Box::new(child)));
                                }
                            }
                            // else: this is the top-level criteria, keep it
                        }
                        "title" => {
                            if let Some(ref mut def) = current_definition {
                                def.metadata.title = Some(std::mem::take(&mut current_text));
                            }
                        }
                        "description" => {
                            if let Some(ref mut def) = current_definition {
                                def.metadata.description = Some(std::mem::take(&mut current_text));
                            }
                        }
                        _ if name.ends_with("_test") => {
                            if let Some(test) = current_test.take() {
                                definitions.tests.insert(test.id.clone(), test);
                            }
                        }
                        _ if name.ends_with("_object") => {
                            if let Some(object) = current_object.take() {
                                definitions.objects.insert(object.id.clone(), object);
                            }
                        }
                        _ if name.ends_with("_state") => {
                            if let Some(state) = current_state.take() {
                                definitions.states.insert(state.id.clone(), state);
                            }
                        }
                        "local_variable" | "constant_variable" | "external_variable" => {
                            if let Some(variable) = current_variable.take() {
                                definitions.variables.insert(variable.id.clone(), variable);
                            }
                        }
                        _ => {}
                    }

                    current_path.pop();
                }
                Ok(Event::Text(ref e)) => {
                    current_text = String::from_utf8_lossy(e.as_ref()).to_string();
                }
                Ok(Event::Eof) => break,
                Err(e) => bail!("Error parsing OVAL XML: {:?}", e),
                _ => {}
            }
            buf.clear();
        }

        Ok(definitions)
    }

    /// Parse OVAL from file
    pub async fn parse_file(path: &str) -> Result<OvalDefinitions> {
        let content = tokio::fs::read_to_string(path).await?;
        Self::parse(&content)
    }

    fn local_name(e: &BytesStart) -> String {
        let full_name = String::from_utf8_lossy(e.name().as_ref()).to_string();
        // Strip namespace prefix if present
        if let Some(pos) = full_name.rfind(':') {
            full_name[pos + 1..].to_string()
        } else {
            full_name
        }
    }

    fn local_name_end(e: &quick_xml::events::BytesEnd) -> String {
        let full_name = String::from_utf8_lossy(e.name().as_ref()).to_string();
        if let Some(pos) = full_name.rfind(':') {
            full_name[pos + 1..].to_string()
        } else {
            full_name
        }
    }

    fn get_attr(e: &BytesStart, name: &str) -> Result<String> {
        for attr in e.attributes().flatten() {
            if attr.key.as_ref() == name.as_bytes() {
                return Ok(String::from_utf8_lossy(&attr.value).to_string());
            }
        }
        bail!("Missing required attribute: {}", name)
    }

    fn parse_definition_start(e: &BytesStart) -> Result<OvalDefinition> {
        let mut def = OvalDefinition {
            id: String::new(),
            version: 0,
            class: DefinitionClass::Compliance,
            status: DefinitionStatus::Draft,
            metadata: OvalMetadata::default(),
            criteria: None,
            deprecated: false,
        };

        for attr in e.attributes().flatten() {
            match attr.key.as_ref() {
                b"id" => {
                    def.id = String::from_utf8_lossy(&attr.value).to_string();
                }
                b"version" => {
                    def.version = String::from_utf8_lossy(&attr.value)
                        .parse()
                        .unwrap_or(0);
                }
                b"class" => {
                    def.class = Self::parse_definition_class(&String::from_utf8_lossy(&attr.value));
                }
                b"deprecated" => {
                    def.deprecated = attr.value.as_ref() == b"true";
                }
                _ => {}
            }
        }

        Ok(def)
    }

    fn parse_definition_class(s: &str) -> DefinitionClass {
        match s.to_lowercase().as_str() {
            "compliance" => DefinitionClass::Compliance,
            "vulnerability" => DefinitionClass::Vulnerability,
            "inventory" => DefinitionClass::Inventory,
            "patch" => DefinitionClass::Patch,
            "miscellaneous" => DefinitionClass::Miscellaneous,
            _ => DefinitionClass::Compliance,
        }
    }

    fn parse_criteria_start(e: &BytesStart) -> Result<Criteria> {
        let mut criteria = Criteria {
            operator: LogicalOperator::And,
            negate: false,
            children: Vec::new(),
            comment: None,
        };

        for attr in e.attributes().flatten() {
            match attr.key.as_ref() {
                b"operator" => {
                    criteria.operator = match String::from_utf8_lossy(&attr.value).as_ref() {
                        "OR" | "or" => LogicalOperator::Or,
                        "ONE" | "one" => LogicalOperator::One,
                        "XOR" | "xor" => LogicalOperator::Xor,
                        _ => LogicalOperator::And,
                    };
                }
                b"negate" => {
                    criteria.negate = attr.value.as_ref() == b"true";
                }
                b"comment" => {
                    criteria.comment = Some(String::from_utf8_lossy(&attr.value).to_string());
                }
                _ => {}
            }
        }

        Ok(criteria)
    }

    fn parse_criterion(e: &BytesStart) -> Result<Criterion> {
        let mut criterion = Criterion {
            test_ref: String::new(),
            negate: false,
            comment: None,
        };

        for attr in e.attributes().flatten() {
            match attr.key.as_ref() {
                b"test_ref" => {
                    criterion.test_ref = String::from_utf8_lossy(&attr.value).to_string();
                }
                b"negate" => {
                    criterion.negate = attr.value.as_ref() == b"true";
                }
                b"comment" => {
                    criterion.comment = Some(String::from_utf8_lossy(&attr.value).to_string());
                }
                _ => {}
            }
        }

        Ok(criterion)
    }

    fn parse_test_start(e: &BytesStart) -> Result<OvalTest> {
        let mut test = OvalTest {
            id: String::new(),
            version: 0,
            comment: None,
            check_existence: ExistenceCheck::AtLeastOneExists,
            check: CheckEnumeration::All,
            object_ref: String::new(),
            state_ref: None,
            state_operator: None,
        };

        for attr in e.attributes().flatten() {
            match attr.key.as_ref() {
                b"id" => {
                    test.id = String::from_utf8_lossy(&attr.value).to_string();
                }
                b"version" => {
                    test.version = String::from_utf8_lossy(&attr.value)
                        .parse()
                        .unwrap_or(0);
                }
                b"comment" => {
                    test.comment = Some(String::from_utf8_lossy(&attr.value).to_string());
                }
                b"check" => {
                    test.check = Self::parse_check_enumeration(&String::from_utf8_lossy(&attr.value));
                }
                b"check_existence" => {
                    test.check_existence = Self::parse_existence_check(&String::from_utf8_lossy(&attr.value));
                }
                b"state_operator" => {
                    test.state_operator = Some(match String::from_utf8_lossy(&attr.value).as_ref() {
                        "OR" | "or" => LogicalOperator::Or,
                        "XOR" | "xor" => LogicalOperator::Xor,
                        "ONE" | "one" => LogicalOperator::One,
                        _ => LogicalOperator::And,
                    });
                }
                _ => {}
            }
        }

        Ok(test)
    }

    fn parse_existence_check(s: &str) -> ExistenceCheck {
        match s {
            "all_exist" => ExistenceCheck::AllExist,
            "any_exist" => ExistenceCheck::AnyExist,
            "at_least_one_exists" => ExistenceCheck::AtLeastOneExists,
            "none_exist" => ExistenceCheck::NoneExist,
            "only_one_exists" => ExistenceCheck::OnlyOneExists,
            _ => ExistenceCheck::AtLeastOneExists,
        }
    }

    fn parse_check_enumeration(s: &str) -> CheckEnumeration {
        match s {
            "all" => CheckEnumeration::All,
            "at least one" | "at_least_one" => CheckEnumeration::AtLeastOne,
            "none exist" | "none_exist" => CheckEnumeration::NoneExist,
            "none satisfy" | "none_satisfy" => CheckEnumeration::NoneSatisfy,
            "only one" | "only_one" => CheckEnumeration::OnlyOne,
            _ => CheckEnumeration::All,
        }
    }

    fn parse_object_start(e: &BytesStart, name: &str) -> Result<OvalObject> {
        let mut object = OvalObject {
            id: String::new(),
            version: 0,
            comment: None,
            object_type: Self::name_to_object_type(name),
            data: std::collections::HashMap::new(),
        };

        for attr in e.attributes().flatten() {
            match attr.key.as_ref() {
                b"id" => {
                    object.id = String::from_utf8_lossy(&attr.value).to_string();
                }
                b"version" => {
                    object.version = String::from_utf8_lossy(&attr.value)
                        .parse()
                        .unwrap_or(0);
                }
                b"comment" => {
                    object.comment = Some(String::from_utf8_lossy(&attr.value).to_string());
                }
                _ => {}
            }
        }

        Ok(object)
    }

    fn parse_state_start(e: &BytesStart, name: &str) -> Result<OvalState> {
        let mut state = OvalState {
            id: String::new(),
            version: 0,
            comment: None,
            state_type: Self::name_to_object_type(name),
            data: std::collections::HashMap::new(),
        };

        for attr in e.attributes().flatten() {
            match attr.key.as_ref() {
                b"id" => {
                    state.id = String::from_utf8_lossy(&attr.value).to_string();
                }
                b"version" => {
                    state.version = String::from_utf8_lossy(&attr.value)
                        .parse()
                        .unwrap_or(0);
                }
                b"comment" => {
                    state.comment = Some(String::from_utf8_lossy(&attr.value).to_string());
                }
                _ => {}
            }
        }

        Ok(state)
    }

    fn parse_variable_start(e: &BytesStart, name: &str) -> Result<OvalVariable> {
        let var_type = match name {
            "local_variable" => VariableType::Local,
            "constant_variable" => VariableType::Constant,
            "external_variable" => VariableType::External,
            _ => VariableType::Local,
        };

        let mut variable = OvalVariable {
            id: String::new(),
            version: 0,
            comment: None,
            datatype: DataType::String,
            variable_type: var_type,
            values: Vec::new(),
        };

        for attr in e.attributes().flatten() {
            match attr.key.as_ref() {
                b"id" => {
                    variable.id = String::from_utf8_lossy(&attr.value).to_string();
                }
                b"version" => {
                    variable.version = String::from_utf8_lossy(&attr.value)
                        .parse()
                        .unwrap_or(0);
                }
                b"comment" => {
                    variable.comment = Some(String::from_utf8_lossy(&attr.value).to_string());
                }
                b"datatype" => {
                    variable.datatype = Self::parse_datatype(&String::from_utf8_lossy(&attr.value));
                }
                _ => {}
            }
        }

        Ok(variable)
    }

    fn parse_datatype(s: &str) -> DataType {
        match s {
            "string" => DataType::String,
            "int" | "integer" => DataType::Int,
            "boolean" | "bool" => DataType::Boolean,
            "float" => DataType::Float,
            "binary" => DataType::Binary,
            "evr_string" => DataType::EvrsString,
            "version" => DataType::Version,
            "ipv4_address" => DataType::Ipv4Address,
            "ipv6_address" => DataType::Ipv6Address,
            _ => DataType::String,
        }
    }

    fn name_to_object_type(name: &str) -> ObjectType {
        // Strip _object or _state suffix and map to ObjectType
        let base = name.trim_end_matches("_object").trim_end_matches("_state");
        match base {
            "file" => ObjectType::UnixFile,
            "password" => ObjectType::UnixPassword,
            "shadow" => ObjectType::UnixShadow,
            "process" | "process58" => ObjectType::UnixProcess,
            "uname" => ObjectType::UnixUname,
            "interface" => ObjectType::UnixInterface,
            "sysctl" => ObjectType::UnixSysctl,
            "dpkginfo" => ObjectType::LinuxDpkgInfo,
            "rpminfo" => ObjectType::LinuxRpmInfo,
            "partition" => ObjectType::LinuxPartition,
            "systemdunitproperty" | "systemdunitdependency" => ObjectType::LinuxSystemdUnit,
            "registry" => ObjectType::WinRegistry,
            "wmi" | "wmi57" => ObjectType::WinWmi,
            "service" => ObjectType::WinService,
            "user" | "user_sid" | "user_sid55" => ObjectType::WinUser,
            "group" | "group_sid" => ObjectType::WinGroup,
            "auditeventpolicy" | "auditeventpolicysubcategories" => ObjectType::WinAuditEventPolicy,
            "lockoutpolicy" => ObjectType::WinLockoutPolicy,
            "passwordpolicy" => ObjectType::WinPasswordPolicy,
            "family" => ObjectType::IndFamily,
            "textfilecontent" | "textfilecontent54" => ObjectType::IndTextFileContent,
            "variable" => ObjectType::IndVariable,
            "environmentvariable" | "environmentvariable58" => ObjectType::IndEnvironmentVariable,
            "sql" | "sql57" => ObjectType::IndSql,
            "filehash" | "filehash58" => ObjectType::IndFileHash,
            _ => ObjectType::IndFamily, // Default fallback
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple_oval() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
        <oval_definitions xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5">
            <definitions>
                <definition id="oval:test:def:1" version="1" class="compliance">
                    <title>Test Definition</title>
                    <description>A test definition</description>
                    <criteria operator="AND">
                        <criterion test_ref="oval:test:tst:1" comment="Test check"/>
                    </criteria>
                </definition>
            </definitions>
            <tests>
                <file_test id="oval:test:tst:1" version="1" check="all" check_existence="all_exist"/>
            </tests>
        </oval_definitions>"#;

        let defs = OvalParser::parse(xml).unwrap();
        assert!(defs.definitions.contains_key("oval:test:def:1"));
    }

    #[test]
    fn test_parse_definition_class() {
        assert!(matches!(OvalParser::parse_definition_class("compliance"), DefinitionClass::Compliance));
        assert!(matches!(OvalParser::parse_definition_class("vulnerability"), DefinitionClass::Vulnerability));
        assert!(matches!(OvalParser::parse_definition_class("patch"), DefinitionClass::Patch));
    }

    #[test]
    fn test_parse_existence_check() {
        assert!(matches!(OvalParser::parse_existence_check("all_exist"), ExistenceCheck::AllExist));
        assert!(matches!(OvalParser::parse_existence_check("none_exist"), ExistenceCheck::NoneExist));
        assert!(matches!(OvalParser::parse_existence_check("at_least_one_exists"), ExistenceCheck::AtLeastOneExists));
    }
}
