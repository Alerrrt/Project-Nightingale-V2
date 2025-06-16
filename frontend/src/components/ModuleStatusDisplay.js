import React from 'react';
import { Box, Typography, Paper, List, ListItem, LinearProgress } from '@mui/material';

const ModuleStatusDisplay = ({ moduleStatuses }) => {
  const modules = Object.values(moduleStatuses);

  if (modules.length === 0) {
    return null; // Don't render if no module statuses are available yet
  }

  return (
    <Box sx={{ width: '100%', mt: 2 }}>
      <Typography variant="h6" gutterBottom component="div">Module Statuses</Typography>
      <Paper sx={{ p: 2 }}>
        <List>
          {modules.map((module, idx) => (
            <ListItem key={module.module_name || idx} sx={{ flexDirection: 'column', alignItems: 'flex-start' }}>
              <Typography component="div" variant="body1" sx={{ width: '100%' }}>
                {`${module.module_name || 'Unknown Module'}: ${module.status}`}
              </Typography>
              <Box sx={{ width: '100%', mt: 0.5, mr: 1 }}>
                <LinearProgress variant="determinate" value={module.progress} sx={{ height: 5 }} />
                <Typography component="div" variant="body2" color="text.secondary">
                  {module.progress}% Complete
                </Typography>
              </Box>
            </ListItem>
          ))}
        </List>
      </Paper>
    </Box>
  );
};

export default ModuleStatusDisplay; 