{{ define "admin_page" }}
{{ template "admin_style" }}
    <div class="container is-fluid" x-data="admin">
		{{ template "admin_header_component" }}
		<div class="container">
            {{ template "admin_statistics_component" .StatsCtx }}
			{{ template "admin_page_filters" }}
			{{ template "admin_page_user_table" .TableCtx }}
		</div>
	</div>
	{{ template "admin_page_alpine_functions" }}
{{ end }}