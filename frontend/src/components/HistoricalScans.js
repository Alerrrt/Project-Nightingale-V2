import React from 'react';
import { Table, TableBody, TableCell, TableContainer, TableHead, TableRow, Paper, Typography } from '@mui/material';
import { Skeleton } from './ui/Skeleton';
import { motion } from 'framer-motion';

export const HistoricalScans = ({ historicalScans, onScanSelect, isLoading }) => {
  if (isLoading) {
    return (
      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        className="space-y-4"
      >
        <Skeleton className="h-8 w-48" />
        <div className="space-y-2">
          <div className="flex items-center space-x-4 p-4 border rounded-lg">
            <Skeleton className="h-4 w-1/3" />
            <Skeleton className="h-4 w-1/4" />
            <Skeleton className="h-4 w-1/4" />
          </div>
          {[...Array(3)].map((_, index) => (
            <div key={index} className="flex items-center space-x-4 p-4 border rounded-lg">
              <Skeleton className="h-4 w-1/3" />
              <Skeleton className="h-4 w-1/4" />
              <Skeleton className="h-4 w-1/4" />
            </div>
          ))}
        </div>
      </motion.div>
    );
  }

  if (!historicalScans || historicalScans.length === 0) {
    return <Typography variant="body1">No historical scans available.</Typography>;
  }

  return (
    <motion.div
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      className="space-y-4"
    >
      <Typography variant="h5" gutterBottom>Historical Scans</Typography>
      <TableContainer component={Paper}>
        <Table sx={{ minWidth: 650 }} aria-label="historical scans table">
          <TableHead>
            <TableRow>
              <TableCell>Target</TableCell>
              <TableCell align="right">Scan Date</TableCell>
              <TableCell align="right">Summary</TableCell>
              {/* Add more headers as needed */}
            </TableRow>
          </TableHead>
          <TableBody>
            {historicalScans.map((scan) => (
              <TableRow
                key={scan.scan_id}
                sx={{ '&:last-child td, &:last-child th': { border: 0 }, cursor: 'pointer', '&:hover': { backgroundColor: 'action.hover' } }}
                onClick={() => onScanSelect(scan.scan_id)}
              >
                <TableCell component="th" scope="row">{scan.target}</TableCell>
                <TableCell align="right">{new Date(scan.scanDate).toLocaleString()}</TableCell>
                <TableCell align="right">{/* Add a summary display based on scan data */}</TableCell>
                {/* Add more data cells */}
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </TableContainer>
    </motion.div>
  );
};