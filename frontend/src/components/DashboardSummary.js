import React from 'react';
import { Box, Typography, Paper } from '@mui/material';
import { Skeleton } from './ui/Skeleton';
import { motion } from 'framer-motion';

export const DashboardSummary = ({ scanResults, isLoading }) => {
  if (isLoading) {
    return (
      <Paper sx={{ p: 2, mb: 2 }}>
        <Skeleton className="h-8 w-48 mb-4" />
        <div className="space-y-4">
          <div className="space-y-2">
            <Skeleton className="h-4 w-32" />
            <Skeleton className="h-4 w-24" />
          </div>
          <div className="space-y-2">
            <Skeleton className="h-4 w-40" />
            <div className="space-y-1">
              {[...Array(5)].map((_, index) => (
                <Skeleton key={index} className="h-4 w-24" />
              ))}
            </div>
          </div>
        </div>
      </Paper>
    );
  }

  // Placeholder for calculating the overall security posture score
  const calculateSecurityScore = (results) => {
    if (!results || results.length === 0) {
      return 'N/A';
    }
    // Basic example: score based on the presence of critical/high vulnerabilities
    const criticalFindings = results.filter(finding => finding.severity === 'Critical').length;
    const highFindings = results.filter(finding => finding.severity === 'High').length;

    if (criticalFindings > 0) {
      return 'Poor';
    } else if (highFindings > 0) {
      return 'Fair';
    } else {
      return 'Good';
    }
  };

  const securityScore = calculateSecurityScore(scanResults);

  // Placeholder for counting vulnerabilities by severity
  const countVulnerabilitiesBySeverity = (results) => {
    if (!results) {
      return { Critical: 0, High: 0, Medium: 0, Low: 0, Informational: 0 };
    }
    return results.reduce((acc, finding) => {
      acc[finding.severity] = (acc[finding.severity] || 0) + 1;
      return acc;
    }, {});
  };

  const severityCounts = countVulnerabilitiesBySeverity(scanResults);

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4"
    >
      <Paper sx={{ p: 2, mb: 2 }}>
        <Typography variant="h5" gutterBottom component="div">
          Scan Summary
        </Typography>
        <Box sx={{ mb: 1 }}>
          <Typography variant="body1" component="div">
            <strong>Overall Security Posture:</strong> {securityScore}
          </Typography>
        </Box>
        <Box>
          <Typography variant="body1" component="div">
            <strong>Vulnerability Counts by Severity:</strong>
          </Typography>
          <ul>
            {Object.entries(severityCounts).map(([severity, count]) => (
              <li key={severity}>
                {severity}: {count}
              </li>
            ))}
          </ul>
        </Box>
        {/* Add more summary details here as needed */}
      </Paper>
    </motion.div>
  );
};
