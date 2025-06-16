import React from 'react';
import LinearProgress from '@mui/material/LinearProgress';
import Typography from '@mui/material/Typography';
import Box from '@mui/material/Box';

const ScanProgress = ({ progress }) => {
  return (
    <Box sx={{ width: '100%', mt: 2 }}>
      <Typography variant="h6" gutterBottom>Scan Progress</Typography>
      <LinearProgress variant="determinate" value={progress} sx={{ height: 10 }} />
      <Typography variant="body2" color="text.secondary">{progress}% Complete</Typography>
    </Box>
  );
};

export default ScanProgress;