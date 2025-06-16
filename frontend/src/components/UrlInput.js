import React, { useState } from 'react';
import { TextField, Button, Container, Stack } from '@mui/material'; // Using Material-UI

export const UrlInput = ({ onScanSubmit }) => {
  const [url, setUrl] = useState('');

  const handleInputChange = (event) => {
    setUrl(event.target.value);
  };

  const handleSubmitClick = () => {
    if (url) {
      onScanSubmit(url);
      setUrl(''); // Clear input after submission
    }
  };

  return (
    <Container>
      <Stack direction="row" spacing={2} alignItems="center">
        <TextField
          label="Enter URL"
          variant="outlined"
          fullWidth
          value={url}
          onChange={handleInputChange}
          InputProps={{
            className: 'rounded-lg bg-neutral-700 text-neutral-100 dark:bg-neutral-700 dark:text-neutral-100',
            style: { borderRadius: '0.5rem' } // Ensure rounded corners apply
          }}
          sx={{
            '& .MuiOutlinedInput-root': {
              '& fieldset': {
                borderColor: 'transparent', // Make border transparent initially
              },
              '&:hover fieldset': {
                borderColor: 'transparent', // Keep transparent on hover
              },
              '&.Mui-focused fieldset': {
                borderColor: '#0ea5e9', // Primary color on focus
              },
              borderRadius: '0.5rem', // Apply border-radius to the root
            },
            '& .MuiInputLabel-root': {
                color: 'rgba(255, 255, 255, 0.7)', // Light gray for label
            },
            '& .MuiInputLabel-root.Mui-focused': {
                color: '#0ea5e9', // Primary color for focused label
            },
          }}
        />
        <Button
          variant="contained"
          color="primary"
          onClick={handleSubmitClick}
          disabled={!url}
        >
          Scan
        </Button>
      </Stack>
    </Container>
  );
};