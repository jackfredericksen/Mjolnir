use rand::Rng;
use serde::{Deserialize, Serialize};

/// Simulated Quantum Annealing (SQA) Optimizer.
///
/// Instead of classical simulated annealing which flips single bits,
/// SQA maintains M "replicas" (Trotter slices) connected by a transverse
/// field coupling. This allows quantum tunneling through energy barriers
/// that trap classical optimizers.
///
/// Used for:
/// 1. Feature selection — finding the optimal subset of features
/// 2. Hyperparameter optimization for the ensemble classifier
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SQAOptimizer {
    /// Number of Trotter replicas (quantum copies of the system)
    pub num_replicas: usize,
    /// Number of annealing steps
    pub num_steps: usize,
    /// Initial transverse field strength (controls quantum tunneling)
    pub initial_gamma: f64,
    /// Final transverse field strength (should be near zero)
    pub final_gamma: f64,
    /// Classical temperature parameter
    pub temperature: f64,
}

impl Default for SQAOptimizer {
    fn default() -> Self {
        Self {
            num_replicas: 16,
            num_steps: 500,
            initial_gamma: 4.0,
            final_gamma: 0.01,
            temperature: 0.5,
        }
    }
}

impl SQAOptimizer {
    /// Run quantum annealing-inspired optimization to select features.
    ///
    /// # Arguments
    /// * `dims` - Number of binary variables (features to select from)
    /// * `cost_fn` - Cost function that takes a binary selection vector
    ///               and returns a cost to minimize
    ///
    /// # Returns
    /// Optimal binary selection vector (true = feature selected)
    pub fn optimize<F>(&self, dims: usize, cost_fn: F) -> Vec<bool>
    where
        F: Fn(&[bool]) -> f64,
    {
        let mut rng = rand::thread_rng();

        // Initialize M replicas with random binary configurations
        let mut replicas: Vec<Vec<bool>> = (0..self.num_replicas)
            .map(|_| (0..dims).map(|_| rng.gen_bool(0.5)).collect())
            .collect();

        let mut best_solution = replicas[0].clone();
        let mut best_cost = cost_fn(&best_solution);

        // Evaluate initial costs for all replicas
        let mut costs: Vec<f64> = replicas.iter().map(|r| cost_fn(r)).collect();

        for step in 0..self.num_steps {
            // Linearly anneal the transverse field
            let progress = step as f64 / self.num_steps as f64;
            let gamma = self.initial_gamma * (1.0 - progress) + self.final_gamma * progress;

            // Coupling strength between adjacent replicas (from Suzuki-Trotter decomposition)
            let j_perp = -0.5
                * self.temperature
                * ((gamma * self.temperature / self.num_replicas as f64)
                    .tanh()
                    .max(1e-10))
                .ln();

            // For each replica
            for r in 0..self.num_replicas {
                // For each spin (feature)
                for i in 0..dims {
                    // Compute energy change from flipping spin i

                    // Classical contribution: change in cost function
                    let mut flipped = replicas[r].clone();
                    flipped[i] = !flipped[i];
                    let delta_classical = cost_fn(&flipped) - costs[r];

                    // Quantum contribution: coupling to same spin in adjacent replicas
                    let prev_replica = if r == 0 {
                        self.num_replicas - 1
                    } else {
                        r - 1
                    };
                    let next_replica = (r + 1) % self.num_replicas;

                    let current_spin: f64 = if replicas[r][i] { 1.0 } else { -1.0 };
                    let prev_spin: f64 = if replicas[prev_replica][i] {
                        1.0
                    } else {
                        -1.0
                    };
                    let next_spin: f64 = if replicas[next_replica][i] {
                        1.0
                    } else {
                        -1.0
                    };

                    // Flipping removes current couplings and creates new ones
                    let delta_quantum =
                        2.0 * j_perp * current_spin * (prev_spin + next_spin);

                    // Total energy change (normalized by replica count)
                    let delta_total =
                        delta_classical / self.num_replicas as f64 + delta_quantum;

                    // Metropolis acceptance
                    let accept = if delta_total <= 0.0 {
                        true
                    } else {
                        let prob = (-delta_total / self.temperature).exp();
                        rng.gen::<f64>() < prob
                    };

                    if accept {
                        replicas[r][i] = !replicas[r][i];
                        costs[r] = cost_fn(&replicas[r]);

                        // Track best solution
                        if costs[r] < best_cost {
                            best_cost = costs[r];
                            best_solution = replicas[r].clone();
                        }
                    }
                }
            }
        }

        best_solution
    }

    /// Select features using SQA: minimizes classification error
    /// while penalizing too many features (Occam's razor).
    pub fn select_features(
        &self,
        num_features: usize,
        samples: &[Vec<f64>],
        labels: &[bool],
        feature_penalty: f64,
    ) -> Vec<usize> {
        let cost_fn = |selection: &[bool]| -> f64 {
            let selected: Vec<usize> = selection
                .iter()
                .enumerate()
                .filter(|(_, &s)| s)
                .map(|(i, _)| i)
                .collect();

            if selected.is_empty() {
                return f64::MAX;
            }

            // Simple separability metric: how well selected features separate classes
            let mut malware_mean = vec![0.0; selected.len()];
            let mut benign_mean = vec![0.0; selected.len()];
            let mut malware_count = 0.0;
            let mut benign_count = 0.0;

            for (sample, &label) in samples.iter().zip(labels.iter()) {
                let values: Vec<f64> = selected.iter().map(|&i| sample[i]).collect();
                if label {
                    for (j, v) in values.iter().enumerate() {
                        malware_mean[j] += v;
                    }
                    malware_count += 1.0;
                } else {
                    for (j, v) in values.iter().enumerate() {
                        benign_mean[j] += v;
                    }
                    benign_count += 1.0;
                }
            }

            if malware_count == 0.0 || benign_count == 0.0 {
                return f64::MAX;
            }

            for v in &mut malware_mean {
                *v /= malware_count;
            }
            for v in &mut benign_mean {
                *v /= benign_count;
            }

            // Fisher's criterion: maximize between-class variance / within-class variance
            let between_class: f64 = malware_mean
                .iter()
                .zip(benign_mean.iter())
                .map(|(m, b)| (m - b).powi(2))
                .sum();

            // We minimize cost, so negate the separability
            let separability_cost = -between_class;

            // Penalty for selecting too many features
            let penalty = feature_penalty * selected.len() as f64;

            separability_cost + penalty
        };

        let selection = self.optimize(num_features, cost_fn);

        selection
            .iter()
            .enumerate()
            .filter(|(_, &s)| s)
            .map(|(i, _)| i)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sqa_finds_minimum() {
        let optimizer = SQAOptimizer {
            num_replicas: 8,
            num_steps: 100,
            initial_gamma: 3.0,
            final_gamma: 0.01,
            temperature: 0.5,
        };

        // Simple cost: minimize number of selected bits
        let result = optimizer.optimize(10, |bits| {
            bits.iter().filter(|&&b| b).count() as f64
        });

        let selected = result.iter().filter(|&&b| b).count();
        assert!(selected <= 3, "SQA should minimize selections, got {}", selected);
    }

    #[test]
    fn test_feature_selection() {
        let optimizer = SQAOptimizer {
            num_replicas: 8,
            num_steps: 50,
            ..Default::default()
        };

        // Create simple separable data: feature 0 separates classes perfectly
        let samples: Vec<Vec<f64>> = vec![
            vec![0.0, 0.5, 0.3],
            vec![0.1, 0.6, 0.2],
            vec![0.9, 0.4, 0.7],
            vec![1.0, 0.5, 0.8],
        ];
        let labels = vec![false, false, true, true];

        let selected = optimizer.select_features(3, &samples, &labels, 0.1);
        assert!(!selected.is_empty(), "Should select at least one feature");
    }
}
