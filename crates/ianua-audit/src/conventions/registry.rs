//! Every convention check, by layer, in the order the files list them.

use super::{Check, api, app, domain, infra, integrations, plain};

/// The checks `ianua-audit check` runs.
pub(super) const CHECKS: &[Check] = &[
    Check {
        layer: "api",
        name: "handler_files_hold_only_handlers",
        run: api::handler_files_hold_only_handlers,
    },
    Check {
        layer: "api",
        name: "every_handler_is_routed_and_documented",
        run: api::every_handler_is_routed_and_documented,
    },
    Check {
        layer: "api",
        name: "every_context_is_served_and_documented",
        run: api::every_context_is_served_and_documented,
    },
    Check {
        layer: "api",
        name: "the_api_checks_no_right",
        run: api::the_api_checks_no_right,
    },
    Check {
        layer: "api",
        name: "no_em_dashes",
        run: api::no_em_dashes,
    },
    Check {
        layer: "api",
        name: "every_function_and_test_is_documented",
        run: api::every_function_and_test_is_documented,
    },
    Check {
        layer: "api",
        name: "bodies_are_taken_through_the_platform_json",
        run: api::bodies_are_taken_through_the_platform_json,
    },
    Check {
        layer: "api",
        name: "a_planted_framework_json_is_caught",
        run: api::a_planted_framework_json_is_caught,
    },
    Check {
        layer: "api",
        name: "queries_and_forms_are_taken_through_the_platform_extractors",
        run: api::queries_and_forms_are_taken_through_the_platform_extractors,
    },
    Check {
        layer: "api",
        name: "a_planted_framework_query_or_form_is_caught",
        run: api::a_planted_framework_query_or_form_is_caught,
    },
    Check {
        layer: "api",
        name: "every_time_in_the_json_is_rfc3339",
        run: api::every_time_in_the_json_is_rfc3339,
    },
    Check {
        layer: "api",
        name: "a_planted_time_in_the_default_form_is_caught",
        run: api::a_planted_time_in_the_default_form_is_caught,
    },
    Check {
        layer: "app",
        name: "no_body_is_written_twice",
        run: app::duplicates::no_body_is_written_twice,
    },
    Check {
        layer: "app",
        name: "no_helper_is_written_twice_under_one_name",
        run: app::duplicates::no_helper_is_written_twice_under_one_name,
    },
    Check {
        layer: "app",
        name: "every_duplicate_check_finds_its_planted_copy",
        run: app::duplicates::every_duplicate_check_finds_its_planted_copy,
    },
    Check {
        layer: "app",
        name: "layout_does_not_change_what_counts_as_the_same",
        run: app::duplicates::layout_does_not_change_what_counts_as_the_same,
    },
    Check {
        layer: "app",
        name: "the_app_builds_no_event_of_its_own",
        run: app::events::the_app_builds_no_event_of_its_own,
    },
    Check {
        layer: "app",
        name: "every_event_macro_is_read",
        run: app::events::every_event_macro_is_read,
    },
    Check {
        layer: "app",
        name: "every_event_check_finds_its_planted_break",
        run: app::events::every_event_check_finds_its_planted_break,
    },
    Check {
        layer: "app",
        name: "every_use_case_has_a_file_of_its_own",
        run: app::every_use_case_has_a_file_of_its_own,
    },
    Check {
        layer: "app",
        name: "no_use_case_takes_a_bare_id_as_its_caller",
        run: app::no_use_case_takes_a_bare_id_as_its_caller,
    },
    Check {
        layer: "app",
        name: "only_acting_builds_a_proof_of_who_acts",
        run: app::only_acting_builds_a_proof_of_who_acts,
    },
    Check {
        layer: "app",
        name: "only_the_run_driver_makes_a_run_caller",
        run: app::only_the_run_driver_makes_a_run_caller,
    },
    Check {
        layer: "app",
        name: "use_cases_ask_acting_through_its_traits",
        run: app::use_cases_ask_acting_through_its_traits,
    },
    Check {
        layer: "app",
        name: "assumed_proofs_stay_in_tests",
        run: app::assumed_proofs_stay_in_tests,
    },
    Check {
        layer: "app",
        name: "no_use_case_checks_a_permission_by_hand",
        run: app::no_use_case_checks_a_permission_by_hand,
    },
    Check {
        layer: "app",
        name: "nothing_asks_the_old_authorizer",
        run: app::nothing_asks_the_old_authorizer,
    },
    Check {
        layer: "app",
        name: "ports_take_typed_values",
        run: app::ports_take_typed_values,
    },
    Check {
        layer: "app",
        name: "ports_own_the_types_they_carry",
        run: app::ports_own_the_types_they_carry,
    },
    Check {
        layer: "app",
        name: "every_check_finds_its_planted_break",
        run: app::every_check_finds_its_planted_break,
    },
    Check {
        layer: "app",
        name: "no_file_repeats_its_folder",
        run: app::naming::no_file_repeats_its_folder,
    },
    Check {
        layer: "app",
        name: "no_use_case_type_repeats_its_folder",
        run: app::naming::no_use_case_type_repeats_its_folder,
    },
    Check {
        layer: "app",
        name: "no_path_climbs_with_super",
        run: app::naming::no_path_climbs_with_super,
    },
    Check {
        layer: "app",
        name: "every_listed_name_still_exists",
        run: app::naming::every_listed_name_still_exists,
    },
    Check {
        layer: "app",
        name: "every_naming_check_finds_its_planted_repeat",
        run: app::naming::every_naming_check_finds_its_planted_repeat,
    },
    Check {
        layer: "app",
        name: "every_step_process_is_picked_up_by_the_sweep",
        run: app::recovery::every_step_process_is_picked_up_by_the_sweep,
    },
    Check {
        layer: "app",
        name: "the_sweep_records_nothing",
        run: app::recovery::the_sweep_records_nothing,
    },
    Check {
        layer: "app",
        name: "sweeps_over_every_tenant_reach_every_tenant",
        run: app::recovery::sweeps_over_every_tenant_reach_every_tenant,
    },
    Check {
        layer: "app",
        name: "a_tenant_never_announces_itself_again",
        run: app::recovery::a_tenant_never_announces_itself_again,
    },
    Check {
        layer: "app",
        name: "every_recovery_check_finds_its_planted_break",
        run: app::recovery::every_recovery_check_finds_its_planted_break,
    },
    Check {
        layer: "app",
        name: "rights_are_checked_before_a_load_they_do_not_need",
        run: app::security::rights_are_checked_before_a_load_they_do_not_need,
    },
    Check {
        layer: "app",
        name: "every_command_records_through_its_auditor",
        run: app::security::every_command_records_through_its_auditor,
    },
    Check {
        layer: "app",
        name: "every_save_is_followed_by_its_events",
        run: app::security::every_save_is_followed_by_its_events,
    },
    Check {
        layer: "app",
        name: "a_store_taking_a_scoped_tenant_is_tenant_scoped",
        run: app::security::a_store_taking_a_scoped_tenant_is_tenant_scoped,
    },
    Check {
        layer: "app",
        name: "every_scoped_port_method_takes_the_tenant_first",
        run: app::security::every_scoped_port_method_takes_the_tenant_first,
    },
    Check {
        layer: "app",
        name: "every_security_exception_still_matches_a_break",
        run: app::security::every_security_exception_still_matches_a_break,
    },
    Check {
        layer: "app",
        name: "every_security_exception_gives_its_reason",
        run: app::security::every_security_exception_gives_its_reason,
    },
    Check {
        layer: "app",
        name: "every_security_rule_finds_its_planted_break",
        run: app::security::every_security_rule_finds_its_planted_break,
    },
    Check {
        layer: "app",
        name: "free_functions_sit_below_the_use_case_in_order",
        run: app::shape::free_functions_sit_below_the_use_case_in_order,
    },
    Check {
        layer: "app",
        name: "commands_save_before_they_record",
        run: app::shape::commands_save_before_they_record,
    },
    Check {
        layer: "app",
        name: "every_ports_struct_derives_fakes",
        run: app::shape::every_ports_struct_derives_fakes,
    },
    Check {
        layer: "app",
        name: "every_plan_limit_is_enforced_by_a_use_case",
        run: app::shape::every_plan_limit_is_enforced_by_a_use_case,
    },
    Check {
        layer: "app",
        name: "every_limit_check_has_a_rejection_test",
        run: app::shape::every_limit_check_has_a_rejection_test,
    },
    Check {
        layer: "app",
        name: "the_resource_kinds_are_read_from_the_limits_port",
        run: app::shape::the_resource_kinds_are_read_from_the_limits_port,
    },
    Check {
        layer: "app",
        name: "a_limit_no_use_case_names_is_found",
        run: app::shape::a_limit_no_use_case_names_is_found,
    },
    Check {
        layer: "app",
        name: "a_limit_check_without_a_refusing_test_is_found",
        run: app::shape::a_limit_check_without_a_refusing_test_is_found,
    },
    Check {
        layer: "app",
        name: "a_limit_check_with_a_refusing_test_passes",
        run: app::shape::a_limit_check_with_a_refusing_test_passes,
    },
    Check {
        layer: "app",
        name: "a_ports_struct_without_the_derive_is_found",
        run: app::shape::a_ports_struct_without_the_derive_is_found,
    },
    Check {
        layer: "app",
        name: "a_ports_struct_with_the_derive_passes",
        run: app::shape::a_ports_struct_with_the_derive_passes,
    },
    Check {
        layer: "app",
        name: "a_free_function_above_the_use_case_is_found",
        run: app::shape::a_free_function_above_the_use_case_is_found,
    },
    Check {
        layer: "app",
        name: "an_event_builder_before_a_check_is_found",
        run: app::shape::an_event_builder_before_a_check_is_found,
    },
    Check {
        layer: "app",
        name: "a_record_before_the_save_is_found",
        run: app::shape::a_record_before_the_save_is_found,
    },
    Check {
        layer: "app",
        name: "function_bodies_carry_no_comments",
        run: app::style::function_bodies_carry_no_comments,
    },
    Check {
        layer: "app",
        name: "no_if_is_nested_in_another",
        run: app::style::no_if_is_nested_in_another,
    },
    Check {
        layer: "app",
        name: "every_allow_says_why",
        run: app::style::every_allow_says_why,
    },
    Check {
        layer: "app",
        name: "the_app_uses_no_adapter_library",
        run: app::style::the_app_uses_no_adapter_library,
    },
    Check {
        layer: "app",
        name: "the_test_module_comes_last_and_alone",
        run: app::style::the_test_module_comes_last_and_alone,
    },
    Check {
        layer: "app",
        name: "no_file_is_split_by_dividers",
        run: app::style::no_file_is_split_by_dividers,
    },
    Check {
        layer: "app",
        name: "no_file_holds_an_em_dash",
        run: app::style::no_file_holds_an_em_dash,
    },
    Check {
        layer: "app",
        name: "no_file_holds_more_than_one_topic",
        run: app::style::no_file_holds_more_than_one_topic,
    },
    Check {
        layer: "app",
        name: "imports_name_their_source_from_the_crate",
        run: app::style::imports_name_their_source_from_the_crate,
    },
    Check {
        layer: "app",
        name: "no_path_climbs_two_levels",
        run: app::style::no_path_climbs_two_levels,
    },
    Check {
        layer: "app",
        name: "imports_name_what_they_take",
        run: app::style::imports_name_what_they_take,
    },
    Check {
        layer: "app",
        name: "imports_sit_at_the_top_of_their_module",
        run: app::style::imports_sit_at_the_top_of_their_module,
    },
    Check {
        layer: "app",
        name: "each_file_imports_what_it_uses",
        run: app::style::each_file_imports_what_it_uses,
    },
    Check {
        layer: "app",
        name: "every_test_says_what_it_shows",
        run: app::style::every_test_says_what_it_shows,
    },
    Check {
        layer: "app",
        name: "no_function_takes_a_bool",
        run: app::style::no_function_takes_a_bool,
    },
    Check {
        layer: "app",
        name: "no_function_takes_a_tuple",
        run: app::style::no_function_takes_a_tuple,
    },
    Check {
        layer: "app",
        name: "a_unit_parameter_is_no_tuple",
        run: app::style::a_unit_parameter_is_no_tuple,
    },
    Check {
        layer: "app",
        name: "every_style_check_finds_its_planted_break",
        run: app::style::every_style_check_finds_its_planted_break,
    },
    Check {
        layer: "domain",
        name: "every_record_loads_from_a_row",
        run: domain::every_record_loads_from_a_row,
    },
    Check {
        layer: "domain",
        name: "every_status_machine_moves_through_try_transition",
        run: domain::every_status_machine_moves_through_try_transition,
    },
    Check {
        layer: "domain",
        name: "no_status_is_set_without_its_machine",
        run: domain::no_status_is_set_without_its_machine,
    },
    Check {
        layer: "domain",
        name: "parse_reads_input_and_from_stored_reads_storage",
        run: domain::parse_reads_input_and_from_stored_reads_storage,
    },
    Check {
        layer: "domain",
        name: "no_id_is_a_bare_uuid",
        run: domain::no_id_is_a_bare_uuid,
    },
    Check {
        layer: "domain",
        name: "fresh_uuids_are_made_only_by_the_id_types",
        run: domain::fresh_uuids_are_made_only_by_the_id_types,
    },
    Check {
        layer: "domain",
        name: "no_digest_is_a_bare_string",
        run: domain::no_digest_is_a_bare_string,
    },
    Check {
        layer: "domain",
        name: "text_wrappers_read_from_json_go_through_their_constructor",
        run: domain::text_wrappers_read_from_json_go_through_their_constructor,
    },
    Check {
        layer: "domain",
        name: "function_bodies_carry_no_comments",
        run: domain::function_bodies_carry_no_comments,
    },
    Check {
        layer: "domain",
        name: "every_allow_says_why",
        run: domain::every_allow_says_why,
    },
    Check {
        layer: "domain",
        name: "every_status_refusal_is_an_error_that_converts",
        run: domain::every_status_refusal_is_an_error_that_converts,
    },
    Check {
        layer: "domain",
        name: "events_use_the_event_macros",
        run: domain::events_use_the_event_macros,
    },
    Check {
        layer: "domain",
        name: "the_domain_uses_no_adapter_library",
        run: domain::the_domain_uses_no_adapter_library,
    },
    Check {
        layer: "domain",
        name: "no_if_is_nested_in_another",
        run: domain::no_if_is_nested_in_another,
    },
    Check {
        layer: "domain",
        name: "text_types_are_declared_with_text_value",
        run: domain::text_types_are_declared_with_text_value,
    },
    Check {
        layer: "domain",
        name: "input_is_checked_by_the_shared_rules",
        run: domain::input_is_checked_by_the_shared_rules,
    },
    Check {
        layer: "domain",
        name: "domain_values_are_typed",
        run: domain::domain_values_are_typed,
    },
    Check {
        layer: "domain",
        name: "emailed_links_have_no_shortcuts",
        run: domain::emailed_links_have_no_shortcuts,
    },
    Check {
        layer: "domain",
        name: "proofs_have_no_public_constructor",
        run: domain::proofs_have_no_public_constructor,
    },
    Check {
        layer: "domain",
        name: "no_person_is_optional",
        run: domain::no_person_is_optional,
    },
    Check {
        layer: "domain",
        name: "text_carrying_a_secret_never_prints",
        run: domain::text_carrying_a_secret_never_prints,
    },
    Check {
        layer: "domain",
        name: "secrets_are_compared_in_constant_time",
        run: domain::secrets_are_compared_in_constant_time,
    },
    Check {
        layer: "domain",
        name: "values_guarding_a_rule_are_rebuilt_only_by_their_aggregate",
        run: domain::values_guarding_a_rule_are_rebuilt_only_by_their_aggregate,
    },
    Check {
        layer: "domain",
        name: "every_choice_names_its_cases",
        run: domain::every_choice_names_its_cases,
    },
    Check {
        layer: "domain",
        name: "no_function_takes_a_flag",
        run: domain::no_function_takes_a_flag,
    },
    Check {
        layer: "domain",
        name: "every_listed_choice_is_still_one",
        run: domain::every_listed_choice_is_still_one,
    },
    Check {
        layer: "domain",
        name: "every_creation_and_change_names_its_caller",
        run: domain::every_creation_and_change_names_its_caller,
    },
    Check {
        layer: "domain",
        name: "values_guarding_a_rule_keep_their_fields_private",
        run: domain::values_guarding_a_rule_keep_their_fields_private,
    },
    Check {
        layer: "domain",
        name: "every_guarded_name_still_exists",
        run: domain::every_guarded_name_still_exists,
    },
    Check {
        layer: "domain",
        name: "one_test_module_sits_last_in_each_file",
        run: domain::one_test_module_sits_last_in_each_file,
    },
    Check {
        layer: "domain",
        name: "no_file_is_split_by_divider_comments",
        run: domain::no_file_is_split_by_divider_comments,
    },
    Check {
        layer: "domain",
        name: "no_file_holds_an_em_dash",
        run: domain::no_file_holds_an_em_dash,
    },
    Check {
        layer: "domain",
        name: "json_reaches_a_value_only_through_its_constructor",
        run: domain::json_reaches_a_value_only_through_its_constructor,
    },
    Check {
        layer: "domain",
        name: "dependencies_point_down_the_context_layers",
        run: domain::dependencies_point_down_the_context_layers,
    },
    Check {
        layer: "domain",
        name: "every_context_is_placed_in_a_layer",
        run: domain::every_context_is_placed_in_a_layer,
    },
    Check {
        layer: "domain",
        name: "every_reconstitute_checks_its_row",
        run: domain::every_reconstitute_checks_its_row,
    },
    Check {
        layer: "domain",
        name: "every_payload_key_is_pinned",
        run: domain::every_payload_key_is_pinned,
    },
    Check {
        layer: "domain",
        name: "a_types_methods_sit_in_one_impl",
        run: domain::a_types_methods_sit_in_one_impl,
    },
    Check {
        layer: "domain",
        name: "imports_name_their_source_from_the_crate",
        run: domain::imports_name_their_source_from_the_crate,
    },
    Check {
        layer: "domain",
        name: "no_path_climbs_two_levels",
        run: domain::no_path_climbs_two_levels,
    },
    Check {
        layer: "domain",
        name: "production_code_imports_no_globs",
        run: domain::production_code_imports_no_globs,
    },
    Check {
        layer: "domain",
        name: "imports_sit_at_the_top_of_their_module",
        run: domain::imports_sit_at_the_top_of_their_module,
    },
    Check {
        layer: "domain",
        name: "no_file_repeats_its_folder",
        run: domain::no_file_repeats_its_folder,
    },
    Check {
        layer: "domain",
        name: "no_path_climbs_with_super",
        run: domain::no_path_climbs_with_super,
    },
    Check {
        layer: "domain",
        name: "every_listed_file_name_still_exists",
        run: domain::every_listed_file_name_still_exists,
    },
    Check {
        layer: "domain",
        name: "the_folder_check_finds_its_planted_repeat",
        run: domain::the_folder_check_finds_its_planted_repeat,
    },
    Check {
        layer: "domain",
        name: "every_file_holds_one_topic",
        run: domain::every_file_holds_one_topic,
    },
    Check {
        layer: "domain",
        name: "every_change_is_a_named_action_not_a_setter",
        run: domain::every_change_is_a_named_action_not_a_setter,
    },
    Check {
        layer: "domain",
        name: "nothing_is_rebuilt_from_loose_stored_parts_in_public",
        run: domain::nothing_is_rebuilt_from_loose_stored_parts_in_public,
    },
    Check {
        layer: "domain",
        name: "audit_payloads_record_stable_names",
        run: domain::audit_payloads_record_stable_names,
    },
    Check {
        layer: "domain",
        name: "docs_name_only_the_none_that_is_there",
        run: domain::docs_name_only_the_none_that_is_there,
    },
    Check {
        layer: "domain",
        name: "repeats_are_found_by_the_shared_helper",
        run: domain::repeats_are_found_by_the_shared_helper,
    },
    Check {
        layer: "domain",
        name: "events_keep_their_fields_to_the_domain",
        run: domain::events_keep_their_fields_to_the_domain,
    },
    Check {
        layer: "domain",
        name: "every_event_of_a_listed_folder_is_on_its_list",
        run: domain::every_event_of_a_listed_folder_is_on_its_list,
    },
    Check {
        layer: "domain",
        name: "no_function_takes_an_unexplained_option",
        run: domain::no_function_takes_an_unexplained_option,
    },
    Check {
        layer: "domain",
        name: "every_listed_optional_parameter_is_still_one",
        run: domain::every_listed_optional_parameter_is_still_one,
    },
    Check {
        layer: "domain",
        name: "every_listed_flag_parameter_is_still_one",
        run: domain::every_listed_flag_parameter_is_still_one,
    },
    Check {
        layer: "domain",
        name: "each_file_imports_what_it_uses",
        run: domain::each_file_imports_what_it_uses,
    },
    Check {
        layer: "domain",
        name: "every_check_finds_its_planted_break",
        run: domain::every_check_finds_its_planted_break,
    },
    Check {
        layer: "domain",
        name: "only_listed_observations_build_an_event",
        run: domain::observations::only_listed_observations_build_an_event,
    },
    Check {
        layer: "domain",
        name: "every_listed_observation_still_builds_its_event",
        run: domain::observations::every_listed_observation_still_builds_its_event,
    },
    Check {
        layer: "infra",
        name: "no_error_is_turned_into_text",
        run: infra::boundaries::no_error_is_turned_into_text,
    },
    Check {
        layer: "infra",
        name: "no_adapter_panics_without_a_reason",
        run: infra::boundaries::no_adapter_panics_without_a_reason,
    },
    Check {
        layer: "infra",
        name: "no_store_takes_a_connection_of_its_own",
        run: infra::boundaries::no_store_takes_a_connection_of_its_own,
    },
    Check {
        layer: "infra",
        name: "every_query_is_checked_when_it_compiles",
        run: infra::boundaries::every_query_is_checked_when_it_compiles,
    },
    Check {
        layer: "infra",
        name: "every_queue_and_client_is_bounded",
        run: infra::boundaries::every_queue_and_client_is_bounded,
    },
    Check {
        layer: "infra",
        name: "every_boundary_check_finds_its_planted_break",
        run: infra::boundaries::every_boundary_check_finds_its_planted_break,
    },
    Check {
        layer: "infra",
        name: "every_name_goes_through_the_namespace",
        run: infra::namespaces::every_name_goes_through_the_namespace,
    },
    Check {
        layer: "infra",
        name: "the_namers_are_read",
        run: infra::namespaces::the_namers_are_read,
    },
    Check {
        layer: "infra",
        name: "the_namespace_check_finds_its_planted_breaks",
        run: infra::namespaces::the_namespace_check_finds_its_planted_breaks,
    },
    Check {
        layer: "infra",
        name: "every_reference_kind_is_read_back",
        run: infra::references::every_reference_kind_is_read_back,
    },
    Check {
        layer: "infra",
        name: "the_reference_kinds_are_read",
        run: infra::references::the_reference_kinds_are_read,
    },
    Check {
        layer: "infra",
        name: "the_reference_kind_check_finds_its_planted_break",
        run: infra::references::the_reference_kind_check_finds_its_planted_break,
    },
    Check {
        layer: "infra",
        name: "no_file_repeats_its_folder",
        run: infra::naming::no_file_repeats_its_folder,
    },
    Check {
        layer: "infra",
        name: "every_adapter_is_named_by_its_provider_and_port",
        run: infra::naming::every_adapter_is_named_by_its_provider_and_port,
    },
    Check {
        layer: "infra",
        name: "no_folder_is_crowded",
        run: infra::naming::no_folder_is_crowded,
    },
    Check {
        layer: "infra",
        name: "every_context_folder_is_named_after_its_ports",
        run: infra::naming::every_context_folder_is_named_after_its_ports,
    },
    Check {
        layer: "infra",
        name: "every_listed_file_name_still_exists",
        run: infra::naming::every_listed_file_name_still_exists,
    },
    Check {
        layer: "infra",
        name: "every_naming_check_finds_its_planted_repeat",
        run: infra::naming::every_naming_check_finds_its_planted_repeat,
    },
    Check {
        layer: "infra",
        name: "a_stand_in_is_named_no_and_its_port",
        run: infra::naming::a_stand_in_is_named_no_and_its_port,
    },
    Check {
        layer: "infra",
        name: "no_link_crosses_tenants",
        run: infra::relationships::no_link_crosses_tenants,
    },
    Check {
        layer: "infra",
        name: "every_link_says_what_a_delete_does",
        run: infra::relationships::every_link_says_what_a_delete_does,
    },
    Check {
        layer: "infra",
        name: "every_link_is_indexed",
        run: infra::relationships::every_link_is_indexed,
    },
    Check {
        layer: "infra",
        name: "every_id_column_is_a_link_or_says_why_not",
        run: infra::relationships::every_id_column_is_a_link_or_says_why_not,
    },
    Check {
        layer: "infra",
        name: "every_relationship_check_finds_its_planted_break",
        run: infra::relationships::every_relationship_check_finds_its_planted_break,
    },
    Check {
        layer: "infra",
        name: "every_tenant_table_is_under_row_security",
        run: infra::schema::every_tenant_table_is_under_row_security,
    },
    Check {
        layer: "infra",
        name: "every_table_has_a_primary_key",
        run: infra::schema::every_table_has_a_primary_key,
    },
    Check {
        layer: "infra",
        name: "migrations_run_in_one_plain_sequence",
        run: infra::schema::migrations_run_in_one_plain_sequence,
    },
    Check {
        layer: "infra",
        name: "no_migration_keeps_logic_in_the_database",
        run: infra::schema::no_migration_keeps_logic_in_the_database,
    },
    Check {
        layer: "infra",
        name: "every_schema_check_finds_its_planted_break",
        run: infra::schema::every_schema_check_finds_its_planted_break,
    },
    Check {
        layer: "infra",
        name: "every_column_is_written_and_read",
        run: infra::fields::every_column_is_written_and_read,
    },
    Check {
        layer: "infra",
        name: "the_column_check_finds_its_planted_break",
        run: infra::fields::the_column_check_finds_its_planted_break,
    },
    Check {
        layer: "infra",
        name: "released_migrations_never_change",
        run: infra::released::released_migrations_never_change,
    },
    Check {
        layer: "infra",
        name: "the_released_check_finds_its_planted_break",
        run: infra::released::the_released_check_finds_its_planted_break,
    },
    Check {
        layer: "infra",
        name: "columns_follow_the_migrations_changes",
        run: infra::fields::columns_follow_the_migrations_changes,
    },
    Check {
        layer: "infra",
        name: "a_quoted_default_with_commas_is_one_column",
        run: infra::fields::a_quoted_default_with_commas_is_one_column,
    },
    Check {
        layer: "infra",
        name: "every_query_names_its_columns",
        run: infra::sql::every_query_names_its_columns,
    },
    Check {
        layer: "infra",
        name: "no_query_pages_by_offset",
        run: infra::sql::no_query_pages_by_offset,
    },
    Check {
        layer: "infra",
        name: "no_query_matches_with_a_leading_wildcard",
        run: infra::sql::no_query_matches_with_a_leading_wildcard,
    },
    Check {
        layer: "infra",
        name: "no_query_reads_a_whole_table",
        run: infra::sql::no_query_reads_a_whole_table,
    },
    Check {
        layer: "infra",
        name: "every_query_on_a_tenant_table_names_the_tenant",
        run: infra::sql::every_query_on_a_tenant_table_names_the_tenant,
    },
    Check {
        layer: "infra",
        name: "no_query_runs_in_a_loop",
        run: infra::sql::no_query_runs_in_a_loop,
    },
    Check {
        layer: "infra",
        name: "every_sql_check_finds_its_planted_break",
        run: infra::sql::every_sql_check_finds_its_planted_break,
    },
    Check {
        layer: "infra",
        name: "every_advisory_lock_is_taken_through_scoped_holding",
        run: infra::sql::every_advisory_lock_is_taken_through_scoped_holding,
    },
    Check {
        layer: "infra",
        name: "no_store_writes_its_sql_inline",
        run: infra::sql::no_store_writes_its_sql_inline,
    },
    Check {
        layer: "infra",
        name: "every_query_file_is_used",
        run: infra::sql::every_query_file_is_used,
    },
    Check {
        layer: "infra",
        name: "every_query_file_says_what_it_does",
        run: infra::sql::every_query_file_says_what_it_does,
    },
    Check {
        layer: "infra",
        name: "query_files_are_grouped_by_table",
        run: infra::sql::query_files_are_grouped_by_table,
    },
    Check {
        layer: "infra",
        name: "only_scim_pages_through_the_offset_builder",
        run: infra::sql::only_scim_pages_through_the_offset_builder,
    },
    Check {
        layer: "infra",
        name: "only_the_scim_queries_may_page_by_offset",
        run: infra::sql::only_the_scim_queries_may_page_by_offset,
    },
    Check {
        layer: "infra",
        name: "a_query_file_is_read_without_its_comments",
        run: infra::sql::a_query_file_is_read_without_its_comments,
    },
    Check {
        layer: "infra",
        name: "every_store_keeps_its_mapping_in_a_record_file",
        run: infra::stores::every_store_keeps_its_mapping_in_a_record_file,
    },
    Check {
        layer: "infra",
        name: "every_store_has_tests",
        run: infra::stores::every_store_has_tests,
    },
    Check {
        layer: "infra",
        name: "every_json_column_has_its_shape_pinned",
        run: infra::stores::every_json_column_has_its_shape_pinned,
    },
    Check {
        layer: "infra",
        name: "store_tests_go_through_the_stores",
        run: infra::stores::store_tests_go_through_the_stores,
    },
    Check {
        layer: "infra",
        name: "every_store_check_finds_its_planted_break",
        run: infra::stores::every_store_check_finds_its_planted_break,
    },
    Check {
        layer: "infra",
        name: "function_bodies_carry_no_comments",
        run: infra::style::function_bodies_carry_no_comments,
    },
    Check {
        layer: "infra",
        name: "no_if_is_nested_in_another",
        run: infra::style::no_if_is_nested_in_another,
    },
    Check {
        layer: "infra",
        name: "every_allow_says_why",
        run: infra::style::every_allow_says_why,
    },
    Check {
        layer: "infra",
        name: "the_test_module_comes_last_and_alone",
        run: infra::style::the_test_module_comes_last_and_alone,
    },
    Check {
        layer: "infra",
        name: "no_file_is_split_by_dividers",
        run: infra::style::no_file_is_split_by_dividers,
    },
    Check {
        layer: "infra",
        name: "no_file_holds_an_em_dash",
        run: infra::style::no_file_holds_an_em_dash,
    },
    Check {
        layer: "infra",
        name: "no_file_holds_more_than_one_topic",
        run: infra::style::no_file_holds_more_than_one_topic,
    },
    Check {
        layer: "infra",
        name: "imports_name_their_source_from_the_crate",
        run: infra::style::imports_name_their_source_from_the_crate,
    },
    Check {
        layer: "infra",
        name: "no_path_climbs_two_levels",
        run: infra::style::no_path_climbs_two_levels,
    },
    Check {
        layer: "infra",
        name: "imports_name_what_they_take",
        run: infra::style::imports_name_what_they_take,
    },
    Check {
        layer: "infra",
        name: "imports_sit_at_the_top_of_their_module",
        run: infra::style::imports_sit_at_the_top_of_their_module,
    },
    Check {
        layer: "infra",
        name: "each_file_imports_what_it_uses",
        run: infra::style::each_file_imports_what_it_uses,
    },
    Check {
        layer: "infra",
        name: "every_test_says_what_it_shows",
        run: infra::style::every_test_says_what_it_shows,
    },
    Check {
        layer: "infra",
        name: "no_function_takes_a_bool",
        run: infra::style::no_function_takes_a_bool,
    },
    Check {
        layer: "infra",
        name: "every_style_check_finds_its_planted_break",
        run: infra::style::every_style_check_finds_its_planted_break,
    },
    Check {
        layer: "integrations",
        name: "function_bodies_carry_no_comments",
        run: integrations::function_bodies_carry_no_comments,
    },
    Check {
        layer: "integrations",
        name: "no_if_is_nested_in_another",
        run: integrations::no_if_is_nested_in_another,
    },
    Check {
        layer: "integrations",
        name: "every_allow_says_why",
        run: integrations::every_allow_says_why,
    },
    Check {
        layer: "integrations",
        name: "the_test_module_comes_last_and_alone",
        run: integrations::the_test_module_comes_last_and_alone,
    },
    Check {
        layer: "integrations",
        name: "no_file_is_split_by_dividers",
        run: integrations::no_file_is_split_by_dividers,
    },
    Check {
        layer: "integrations",
        name: "no_file_holds_an_em_dash",
        run: integrations::no_file_holds_an_em_dash,
    },
    Check {
        layer: "integrations",
        name: "no_file_holds_more_than_one_topic",
        run: integrations::no_file_holds_more_than_one_topic,
    },
    Check {
        layer: "integrations",
        name: "imports_name_their_source_from_the_crate",
        run: integrations::imports_name_their_source_from_the_crate,
    },
    Check {
        layer: "integrations",
        name: "no_path_climbs_two_levels",
        run: integrations::no_path_climbs_two_levels,
    },
    Check {
        layer: "integrations",
        name: "imports_name_what_they_take",
        run: integrations::imports_name_what_they_take,
    },
    Check {
        layer: "integrations",
        name: "imports_sit_at_the_top_of_their_module",
        run: integrations::imports_sit_at_the_top_of_their_module,
    },
    Check {
        layer: "integrations",
        name: "each_file_imports_what_it_uses",
        run: integrations::each_file_imports_what_it_uses,
    },
    Check {
        layer: "integrations",
        name: "every_test_says_what_it_shows",
        run: integrations::every_test_says_what_it_shows,
    },
    Check {
        layer: "integrations",
        name: "no_function_takes_a_bool",
        run: integrations::no_function_takes_a_bool,
    },
    Check {
        layer: "integrations",
        name: "every_public_item_says_what_it_is",
        run: integrations::every_public_item_says_what_it_is,
    },
    Check {
        layer: "integrations",
        name: "every_integration_check_finds_its_planted_break",
        run: integrations::every_integration_check_finds_its_planted_break,
    },
    Check {
        layer: "plain",
        name: "actions_are_named_by_their_verb",
        run: plain::actions_are_named_by_their_verb,
    },
    Check {
        layer: "plain",
        name: "names_say_what_they_are",
        run: plain::names_say_what_they_are,
    },
    Check {
        layer: "plain",
        name: "tests_say_what_they_show",
        run: plain::tests_say_what_they_show,
    },
    Check {
        layer: "plain",
        name: "comments_say_what_names_do_not",
        run: plain::comments_say_what_names_do_not,
    },
    Check {
        layer: "plain",
        name: "error_lists_stay_short",
        run: plain::error_lists_stay_short,
    },
    Check {
        layer: "plain",
        name: "comments_hold_no_filler",
        run: plain::comments_hold_no_filler,
    },
    Check {
        layer: "plain",
        name: "names_stay_short",
        run: plain::names_stay_short,
    },
    Check {
        layer: "plain",
        name: "no_function_is_a_second_name",
        run: plain::no_function_is_a_second_name,
    },
    Check {
        layer: "plain",
        name: "comments_are_phrased_plainly",
        run: plain::comments_are_phrased_plainly,
    },
    Check {
        layer: "plain",
        name: "comments_say_what_is_not_what_was",
        run: plain::comments_say_what_is_not_what_was,
    },
    Check {
        layer: "plain",
        name: "the_docs_site_is_plain",
        run: plain::the_docs_site_is_plain,
    },
    Check {
        layer: "plain",
        name: "code_is_cut_where_it_helps",
        run: plain::code_is_cut_where_it_helps,
    },
    Check {
        layer: "plain",
        name: "comments_follow_no_formula",
        run: plain::comments_follow_no_formula,
    },
    Check {
        layer: "plain",
        name: "drafts_leave_nothing_behind",
        run: plain::drafts_leave_nothing_behind,
    },
    Check {
        layer: "plain",
        name: "the_plain_code_rules_find_their_planted_breaks",
        run: plain::the_plain_code_rules_find_their_planted_breaks,
    },
    Check {
        layer: "plain",
        name: "the_structure_rules_find_their_planted_breaks",
        run: plain::the_structure_rules_find_their_planted_breaks,
    },
    Check {
        layer: "plain",
        name: "public_items_are_used_outside_their_crate",
        run: plain::public_items_are_used_outside_their_crate,
    },
    Check {
        layer: "plain",
        name: "every_crate_takes_the_shared_lints",
        run: plain::every_crate_takes_the_shared_lints,
    },
    Check {
        layer: "plain",
        name: "the_reach_rules_find_their_planted_breaks",
        run: plain::the_reach_rules_find_their_planted_breaks,
    },
];
