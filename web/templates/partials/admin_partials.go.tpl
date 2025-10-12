{{ define "admin_style" }}
<style>
  .claims-list {
    display: flex;
    flex-wrap: wrap;
    gap: 0.25rem;
    margin-top: 0.5rem;
  }
  .claim-tag {
    font-size: 0.75rem;
  }
  .user-actions {
    white-space: nowrap;
  }
  .table-container {
    background: white;
    border-radius: 6px;
    box-shadow: 0 0.5em 1em -0.125em rgba(10, 10, 10, 0.1);
  }
  .page-header {
    border-bottom: 1px solid #dbdbdb;
    padding: 1.5rem 0;
    margin-bottom: 2rem;
  }

  .stats-card {
    border-radius: 6px;
    box-shadow: 0 0.5em 1em -0.125em rgba(10, 10, 10, 0.1);
    padding: 1.5rem;
    background-color: #ffffff; /* default light */
  }

  .table tr.is-selected {
    background-color: rgba(0, 209, 178, 0.08);
  }

  .flash {
    animation: flash-bg 0.5s ease;
  }

  @keyframes flash-bg {
    0% {
      background-color: #fffa8b;
    } /* bright yellow */
    100% {
      background-color: transparent;
    }
  }

  /* Dark mode overrides */
  @media (prefers-color-scheme: dark) {
    .stats-card {
      background-color: #1e1e1e; /* surface color */
      border: 1px solid rgba(255, 255, 255, 0.05);
      box-shadow: 0 2px 6px rgba(0, 0, 0, 0.6),
        0 0 0 1px rgba(255, 255, 255, 0.04);
    }
    .stats-card:hover {
      background-color: #262626;
      box-shadow: 0 4px 8px rgba(0, 0, 0, 0.7),
        0 0 0 1px rgba(255, 255, 255, 0.08);
    }
    .filter-box {
      background-color: #1e1e1e; /* surface color */
      border: 1px solid rgba(255, 255, 255, 0.05);
      box-shadow: 0 2px 6px rgba(0, 0, 0, 0.6),
        0 0 0 1px rgba(255, 255, 255, 0.04);
    }
    .table tr.is-selected {
      background-color: rgba(0, 209, 178, 0.2);
    }
  }
</style>
{{ end }} {{ define "admin_header_component" }}
<div class="page-header">
  <div class="container">
    <div class="level">
      <div class="level-left">
        <div class="level-item">
          <div>
            <h1 class="title is-3">User Management</h1>
            <p class="subtitle is-6">Manage users and their permissions</p>
          </div>
        </div>
      </div>
      <div class="level-right">
        <div class="level-item">
          <button class="button is-primary">
            <span class="icon">
              <i class="fas fa-plus"></i>
            </span>
            <span>Add User</span>
          </button>
        </div>
      </div>
    </div>
  </div>
</div>
{{ end }}
{{ define "admin_statistics_component" }}
<div
  class="columns is-multiline mb-5"
  x-data='{{ .XData }}'
  @update-stats.window="updateStats($event)"
>
  {{ template "admin_statistics_total_card" }} 
  {{ template "admin_statistics_active_card" }} 
  {{ template "admin_statistics_inactive_card" }}
  {{ template "admin_statistics_admin_card" }}
</div>
{{ end }}
{{ define "admin_statistics_total_card" }}
<div class="column is-3">
  <div class="stats-card" :class="{ flash: flashing.total }">
    <div class="level">
      <div class="level-left">
        <div class="level-item">
          <div>
            <p class="heading">Total Users</p>
            <p class="title is-4" x-text="stats.total"></p>
          </div>
        </div>
      </div>
      <div class="level-right">
        <div class="level-item">
          <span class="icon is-large has-text-primary">
            <i class="fas fa-users fa-2x"></i>
          </span>
        </div>
      </div>
    </div>
  </div>
</div>
{{ end }}
{{ define "admin_statistics_active_card" }}
<div class="column is-3">
  <div class="stats-card" :class="{ flash: flashing.active }">
    <div class="level">
      <div class="level-left">
        <div class="level-item">
          <div>
            <p class="heading">Active Users</p>
            <p class="title is-4" x-text="stats.active"></p>
          </div>
        </div>
      </div>
      <div class="level-right">
        <div class="level-item">
          <span class="icon is-large has-text-success">
            <i class="fas fa-user-check fa-2x"></i>
          </span>
        </div>
      </div>
    </div>
  </div>
</div>
{{ end }}

{{ define "admin_statistics_inactive_card" }}
<div class="column is-3">
  <div class="stats-card" :class="{ flash: flashing.inactive }">
    <div class="level">
      <div class="level-left">
        <div class="level-item">
          <div>
            <p class="heading">Inactive Users</p>
            <p class="title is-4" x-text="stats.inactive"></p>
          </div>
        </div>
      </div>
      <div class="level-right">
        <div class="level-item">
          <span class="icon is-large has-text-warning">
            <i class="fas fa-user-clock fa-2x"></i>
          </span>
        </div>
      </div>
    </div>
  </div>
</div>
{{ end }}
{{ define "admin_statistics_admin_card" }}
<div class="column is-3">
  <div class="stats-card" :class="{ flash: flashing.admin }">
    <div class="level">
      <div class="level-left">
        <div class="level-item">
          <div>
            <p class="heading">Admin Users</p>
            <p class="title is-4" x-text="stats.admin"></p>
          </div>
        </div>
      </div>
      <div class="level-right">
        <div class="level-item">
          <span class="icon is-large has-text-danger">
            <i class="fas fa-user-shield fa-2x"></i>
          </span>
        </div>
      </div>
    </div>
  </div>
</div>
{{ end }}
{{ define "admin_page_filters" }}
  <div class="box mb-5 filter-box">
		<div class="columns">
			<div class="column is-4">
				<div class="field">
					<label class="label">Search Users</label>
					<div class="control has-icons-left">
						<input
							class="input"
							type="text"
							placeholder="Search by name or email..."
						/>
						<span class="icon is-small is-left">
							<i class="fas fa-search"></i>
						</span>
					</div>
				</div>
			</div>
			<div class="column is-3">
				<div class="field">
					<label class="label">Status</label>
					<div class="control">
						<div class="select is-fullwidth">
							<select>
								<option>All Status</option>
								<option>Active</option>
								<option>Inactive</option>
								<option>Pending</option>
							</select>
						</div>
					</div>
				</div>
			</div>
			<div class="column is-3">
				<div class="field">
					<label class="label">Claims</label>
					<div class="control">
						<div class="select is-fullwidth">
							<select>
								<option>All Claims</option>
								<option>user.read</option>
								<option>user.write</option>
								<option>admin.full</option>
								<option>reports.view</option>
								<option>billing.manage</option>
							</select>
						</div>
					</div>
				</div>
			</div>
			<div class="column is-2">
				<div class="field">
					<label class="label">&nbsp;</label>
					<div class="control">
						<button class="button is-link is-fullwidth">
							<span class="icon">
								<i class="fas fa-filter"></i>
							</span>
							<span>Filter</span>
						</button>
					</div>
				</div>
			</div>
		</div>
	</div>
{{ end }}

{{ define "admin_page_user_table" }}
  <div class="table-container">
		<table class="table is-fullwidth is-hoverable">
			{{ template "admin_page_user_table_header" }}
			<tbody>
      {{ range .RowCtxs }}
        {{ template "admin_page_user_table_row" . }}
      {{ end }}
			</tbody>
		</table>
	</div>
{{ end }}

{{ define "admin_page_user_table_header" }}
<thead>
		<tr>
			<th>
				<label class="checkbox">
					<input type="checkbox"/>
				</label>
			</th>
			<th>User</th>
			<th>Status</th>
			<th>Claims</th>
			<th>Last Update</th>
			<th>Created</th>
		</tr>
	</thead>
{{ end }}

{{ define "admin_page_user_table_row" }}
  <tr
  hx-get="/admin/users/{{ .ID }}/edit-row"
  hx-target="this"
  hx-swap="outerHTML"
  class="user-row"
>
  <td>
    <label class="checkbox">
      <input type="checkbox" @click.stop />
    </label>
  </td>

  <td>
    <div class="block">
      <p class="is-size-6 has-text-weight-semibold">{{ .Email }}</p>
      <p class="is-size-7 has-text-grey">{{ .Email }}</p>
    </div>
  </td>

  <td>
    {{ if .IsActive }}
      <span class="tag is-success">Active</span>
    {{ else }}
      <span class="tag is-warning">Inactive</span>
    {{ end }}
  </td>

  <td>
    <div class="claims-list">
      {{ range .Claims }}
        <span class="tag claim-tag">{{ . }}</span>
      {{ end }}
    </div>
  </td>

  <td>
    <span class="has-text-grey-dark"
      x-text="timeUtils.formatTime('{{ .UpdatedAt }}')">Loading...</span>
  </td>

  <td>
    <span class="has-text-grey-dark"
      x-text="timeUtils.formatTime('{{ .CreatedAt }}')">Loading...</span>
  </td>
</tr>
{{ end }}

{{ define "admin_page_alpine_functions" }}
<script>
document.addEventListener('alpine:init', () => {
    Alpine.data('admin', () => ({
        timeUtils: {
            formatTime(isoString) {
                if (!isoString) return 'ERR time format';
                const date = new Date(isoString);
                const now = new Date();
                const diffHours = (now.getTime() - date.getTime()) / (1000 * 60 * 60);
                if (diffHours < 1) return `less than an hour ago`;
                if (diffHours < 72) return `${Math.round(diffHours)} hours ago`;
                return date.toLocaleDateString(undefined, { month: 'short', day: 'numeric', year: 'numeric' });
            }
        }
    }));
});
</script>
{{ end }}

{{ define "admin_page_user_table_row_edit" }}
<tr
		class="is-selected"
		x-data={{ .XData }}
	>
		<td colspan="6">
			<div class="p-4">
				<div class="columns">
					<!-- Email column -->
					<div class="column">
						<div class="field">
							<label class="label">Email</label>
							<div class="control">
								<p class="is-size-6 has-text-grey-light is-italic">{{ .Email }}</p>
							</div>
						</div>
					</div>
					<!-- Role column -->
					<div class="column">
						<div class="field">
							<label class="label">Role</label>
							<div class="control">
								<div class="select is-fullwidth">
									<select x-model="userRole">
										<template x-for="role in availableRoles" :key="role">
											<option :value="role" x-text="role" :selected="role === userRole"></option>
										</template>
									</select>
								</div>
							</div>
						</div>
					</div>
				</div>
				<!-- Warning message -->
				<div x-show="showWarning" class="notification is-warning is-light" x-transition>
					<button class="delete" @click="showWarning = false"></button>
					<p x-text="warningMessage"></p>
				</div>
				<div class="field">
					<label class="label">Current Claims</label>
					<div class="field is-grouped is-grouped-multiline">
						<template x-for="(claim, index) in claims" :key="index">
							<div class="control">
								<div class="tags has-addons">
									<span class="tag is-link" x-text="claim"></span>
									<a class="tag is-delete" @click="removeClaim(index)" title="Remove claim"></a>
								</div>
							</div>
						</template>
						<p x-show="claims.length === 0" class="has-text-grey-light is-italic">
							No claims assigned.
						</p>
					</div>
				</div>
				<div class="field">
					<label class="label">Add New Claim</label>
					<div class="field has-addons">
						<div class="control is-expanded">
							<input class="input" type="text" placeholder="Resource (e.g., /orders/*)" x-model="newClaimResource" @keydown.enter.prevent="addClaim()"/>
						</div>
						<div class="control">
							<span class="select">
								<select x-model="newClaimRole">
									<template x-for="role in availableRoles" :key="role">
										<option :value="role" x-text="role" :selected="role === newClaimRole"></option>
									</template>
								</select>
							</span>
						</div>
						<div class="control">
							<button class="button is-info" @click="addClaim()" :disabled="!newClaimResource.trim()">
								Add
							</button>
						</div>
					</div>
				</div>
				<div class="field is-grouped mt-5">
					<div class="control">
						<button
							class="button is-primary"
							hx-put="/admin/users/{{ .ID }}"
							hx-target="closest tr"
							hx-swap="outerHTML"
							:hx-vals="JSON.stringify({ role: userRole, claims: claims })"
						>
							✅ Save
						</button>
					</div>
					<div class="control">
						<button
							class="button"
							hx-get="/admin/users/{{ .ID }}"
							hx-target="closest tr"
							hx-swap="outerHTML"
						>
							❌ Cancel
						</button>
					</div>
					<div class="control is-expanded"></div>
					<div class="control">
						<button
							class="button is-light is-warning"
							hx-post="/admin/users/{{ .ID }}/reset-password"
							hx-swap="none"
						>
							🔑 Reset Password
						</button>
					</div>
          {{ if .IsActive }}
						<div class="control">
							<button
								class="button is-light is-warning"
								hx-post="/admin/users/{{ .ID }}/disable"
								hx-target="closest tr"
								hx-swap="outerHTML"
								hx-confirm="Are you sure you want to disable this user?"
							>
								🚫 Disable
							</button>
						</div>
					{{ else }}
						<div class="control">
							<button
								class="button is-light is-warning"
								hx-post="/admin/users/{{ .ID }}/enable"
								hx-target="closest tr"
								hx-swap="outerHTML"
							>
								🔓 Enable
							</button>
						</div>
					{{ end }}
					<div class="control">
						<button
							class="button is-danger"
							hx-delete="/admin/users/{{ .ID }}"
							hx-target="closest tr"
							hx-swap="outerHTML"
							hx-confirm="Are you sure you want to permanently delete this user? This action cannot be undone."
						>
							🗑️ Delete
						</button>
					</div>
				</div>
			</div>
		</td>
	</tr>
{{ end }}