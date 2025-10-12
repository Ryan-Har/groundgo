package webmodels

import (
	"fmt"
	"html/template"
	"strings"

	"github.com/Ryan-Har/groundgo/pkg/models"
)

func adminPageStatisticsxData(users []*models.User) template.JS {
	var total, active, inactive, admin int
	for _, user := range users {
		total++
		if user.Role.AtLeast(models.RoleAdmin) {
			admin++
		}
		if user.IsActive {
			active++
		} else {
			inactive++
		}
	}

	str := fmt.Sprintf(`{
        stats: {
            total: %d,
            active: %d,
            inactive: %d,
            admin: %d
        },
        flashing: {
            total: false,
            active: false,
            inactive: false,
            admin: false    
        },
        updateStats(event) {
            const updates = event.detail;
            for (const key in updates) {
                if (this.stats.hasOwnProperty(key)) {
                    this.stats[key] += updates[key];
                    this.flashStat(key);
                }
            }
        },
        flashStat(statKey) {
            this.flashing[statKey] = true;
            setTimeout(() => {
                this.flashing[statKey] = false;
            }, 1000);   
        }
    }`, total, active, inactive, admin)

	return template.JS(str)
}

func userRowEditPartialxData(u *models.User) template.JS {

	claimsSlice := u.Claims.AsSlice()
	allRoles := models.ListRoles()

	// Ensure we have a default role
	defaultRole := "guest"
	if len(allRoles) > 0 {
		defaultRole = allRoles[0]
	}

	toJSStringArray := func(arr []string) string {
		var sb strings.Builder
		sb.WriteString("[")
		for i, s := range arr {
			if i > 0 {
				sb.WriteString(",")
			}
			// wrap each string in single quotes
			sb.WriteString("'")
			sb.WriteString(s)
			sb.WriteString("'")
		}
		sb.WriteString("]")
		return sb.String()
	}

	// Build the x-data object manually to avoid HTML escaping issues
	str := fmt.Sprintf(`() => ({
        userRole: '%s',
        claims: %s,
        newClaimResource: '',
        newClaimRole: '%s',
        availableRoles: %s,
        warningMessage: '',
        showWarning: false,
        addClaim() {
			const resource = this.newClaimResource.trim();
			if (!resource) return;
			
			const fullClaim = `+"`${resource}:${this.newClaimRole}`"+`;
			
			// Check if resource already exists
			const existingIndex = this.claims.findIndex(claim => 
				claim.split(':')[0] === resource
			);
			
			if (existingIndex !== -1) {
				const existingClaim = this.claims[existingIndex];
				const existingRole = existingClaim.split(':')[1];
				
				// Show warning and replace
				this.warningMessage = `+"`Resource '${resource}' already exists with role '${existingRole}'. It will be replaced with '${this.newClaimRole}'.`"+`;
				this.showWarning = true;
				
				this.claims.splice(existingIndex, 1);
				this.claims.push(fullClaim);
				
				setTimeout(() => { this.showWarning = false; }, 3000);
			} else {
				this.claims.push(fullClaim);
			}
			
			this.newClaimResource = '';
        },
        removeClaim(index) {
            this.claims.splice(index, 1);
        }
    })`,
		u.Role.String(),
		toJSStringArray(claimsSlice),
		defaultRole,
		toJSStringArray(allRoles))

	return template.JS(str)
}
