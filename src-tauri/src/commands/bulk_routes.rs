#[tauri::command]
pub(crate) fn parse_bulk_cidrs(input: String) -> Result<Vec<String>, String> {
    net_manager_core::cidr_bulk::parse_bulk_cidrs(&input)
        .map(|routes| routes.into_iter().map(|route| route.to_string()).collect())
        .map_err(|_| "Invalid CIDR list (maximum 1 MiB and 8192 routes)".to_string())
}
