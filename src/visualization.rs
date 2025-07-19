use crate::models::Group;
use crate::service::ExpenseService;
use crate::{error::ExpenseServiceError, models::Transaction};
use log::{debug, error};
use serde_json::{Value, json};

// Generates Chart.js configuration for visualizing user balances in a group
pub struct Visualization;

impl Visualization {
    /// Generates a Chart.js bar chart configuration for user balances in a group.
    ///
    /// # Arguments
    /// * `service` - The ExpenseService instance to calculate balances.
    /// * `group` - The group for which to visualize balances.
    /// * `transactions` - List of transactions for the group.
    ///
    /// # Returns
    /// A JSON Value containing the Chart.js configuration, or an error if data cannot be retrieved.
    pub fn generate_balance_chart<'a>(
        service: &ExpenseService<'a>,
        group: &Group,
        transactions: &[Transaction],
    ) -> Result<Value, ExpenseServiceError> {
        debug!(
            "Generating balance chart for group {} with {} transactions",
            group.id,
            transactions.len()
        );

        // Calculate balances using ExpenseService
        let balances = service.calculate_balances(group, transactions);
        if balances.is_empty() {
            error!("No balances found for group {}", group.id);
            return Err(ExpenseServiceError::NoBalancesAvailable);
        }

        // Fetch user names for labels and prepare data
        let mut labels: Vec<String> = Vec::new();
        let mut data: Vec<f64> = Vec::new();
        for (&user_id, &balance) in &balances {
            let user = service.storage.get_user(user_id).ok_or_else(|| {
                error!("User {} not found for group {}", user_id, group.id);
                ExpenseServiceError::UserNotFound
            })?;
            labels.push(user.name);
            data.push(balance);
        }

        debug!("Processed {} users with balances for chart", labels.len());

        // Generate dynamic colors to support any number of users
        let base_colors = vec![
            (75, 192, 192),  // Teal
            (255, 99, 132),  // Red
            (54, 162, 235),  // Blue
            (255, 206, 86),  // Yellow
            (153, 102, 255), // Purple
        ];
        let mut background_colors = Vec::new();
        let mut border_colors = Vec::new();
        for i in 0..labels.len() {
            let (r, g, b) = base_colors[i % base_colors.len()];
            background_colors.push(format!("rgba({}, {}, {}, 0.6)", r, g, b));
            border_colors.push(format!("rgba({}, {}, {}, 1)", r, g, b));
        }

        // Create Chart.js configuration
        let chart_config = json!({
            "type": "bar",
            "data": {
                "labels": labels,
                "datasets": [{
                    "label": "User Balances",
                    "data": data,
                    "backgroundColor": background_colors,
                    "borderColor": border_colors,
                    "borderWidth": 1
                }]
            },
            "options": {
                "scales": {
                    "y": {
                        "beginAtZero": true,
                        "title": {
                            "display": true,
                            "text": "Balance (Currency)"
                        }
                    },
                    "x": {
                        "title": {
                            "display": true,
                            "text": "Users"
                        }
                    }
                },
                "plugins": {
                    "title": {
                        "display": true,
                        "text": format!("Balances for Group: {}", group.name)
                    }
                }
            }
        });

        debug!("Generated Chart.js configuration for group {}", group.id);
        Ok(chart_config)
    }
}
