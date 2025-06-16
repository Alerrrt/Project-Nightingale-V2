import React from 'react';
import { Table, TableBody, TableCell, TableContainer, TableHead, TableRow, Paper } from '@mui/material';
import { SeverityBadge } from './ui/SeverityBadge';
import { Skeleton } from './ui/Skeleton';
import { motion } from 'framer-motion';

export const JsVulnTable = ({ findings, isLoading }) => {
  if (isLoading) {
    return (
      <div className="space-y-4">
        <div className="flex justify-between items-center">
          <Skeleton className="h-8 w-64" />
        </div>
        <div className="space-y-2">
          {[...Array(3)].map((_, index) => (
            <div key={index} className="flex items-center space-x-4 p-4 border rounded-lg">
              <Skeleton className="h-4 w-1/5" />
              <Skeleton className="h-4 w-1/5" />
              <Skeleton className="h-4 w-1/5" />
              <Skeleton className="h-4 w-1/5" />
              <Skeleton className="h-4 w-1/5" />
            </div>
          ))}
        </div>
      </div>
    );
  }

  if (!findings || findings.length === 0) {
    return (
      <div className="text-center py-8">
        <p className="text-neutral-600 dark:text-neutral-300">No vulnerable JavaScript libraries found.</p>
      </div>
    );
  }

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
    >
      <TableContainer component={Paper}>
        <Table>
          <TableHead className="bg-neutral-100 dark:bg-neutral-700 uppercase text-xs text-muted-foreground">
            <TableRow>
              <TableCell>File URL</TableCell>
              <TableCell>Library</TableCell>
              <TableCell>Version</TableCell>
              <TableCell>CVEs</TableCell>
              <TableCell>CWEs</TableCell>
              <TableCell>Severity</TableCell>
              <TableCell>Advisory Link</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {findings.map((finding, index) => {
              const proof = typeof finding.proof === 'string' ? JSON.parse(finding.proof) : finding.proof;
              const cves = proof?.cves?.join(', ') || 'N/A';
              const cweId = finding.cwe_id || 'N/A'; // Assuming cwe_id is directly available
              const advisoryLink = proof?.advisory_link || '#';
              
              return (
                <TableRow
                  key={finding.id || index}
                  hover
                  className="group hover:bg-neutral-50 dark:hover:bg-neutral-800 transition-colors"
                >
                  <TableCell className="w-1/4">{proof?.file_url || finding.affected_url}</TableCell>
                  <TableCell>{proof?.library || 'N/A'}</TableCell>
                  <TableCell>{proof?.version || 'N/A'}</TableCell>
                  <TableCell>{cves}</TableCell>
                  <TableCell>{cweId}</TableCell>
                  <TableCell><SeverityBadge severity={finding.severity} /></TableCell>
                  <TableCell>
                    {advisoryLink !== '#' ? (
                      <a href={advisoryLink} target="_blank" rel="noopener noreferrer" className="text-primary-500 hover:underline">
                        View Advisory
                      </a>
                    ) : 'N/A'}
                  </TableCell>
                </TableRow>
              );
            })}
          </TableBody>
        </Table>
      </TableContainer>
    </motion.div>
  );
}; 