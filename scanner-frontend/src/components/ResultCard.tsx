import React, { useState, useCallback } from 'react';
import { useDebounce } from '../hooks/useDebounce';
import axios from 'axios';
import { toast } from 'react-hot-toast';

interface ResultCardProps {
  id: number;
  url: string;
  moduleId: string;
  snippet: string;
  severity: string;
  initialNotes?: string;
}

const severityOptions = [
  { value: 'low', label: 'Low', color: 'bg-yellow-100 text-yellow-800' },
  { value: 'medium', label: 'Medium', color: 'bg-orange-100 text-orange-800' },
  { value: 'high', label: 'High', color: 'bg-red-100 text-red-800' }
];

export const ResultCard: React.FC<ResultCardProps> = ({
  id,
  url,
  moduleId,
  snippet,
  severity: initialSeverity,
  initialNotes = ''
}) => {
  const [severity, setSeverity] = useState(initialSeverity);
  const [notes, setNotes] = useState(initialNotes);
  const [isEditing, setIsEditing] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Debounce notes updates
  const debouncedUpdate = useDebounce(async (newNotes: string) => {
    try {
      setIsLoading(true);
      setError(null);
      await axios.patch(`/api/results/${id}`, {
        severity,
        notes: newNotes
      });
    } catch (err) {
      setError('Failed to update notes');
      toast.error('Failed to update notes');
    } finally {
      setIsLoading(false);
    }
  }, 500);

  const handleNotesChange = useCallback((e: React.ChangeEvent<HTMLTextAreaElement>) => {
    const newNotes = e.target.value;
    setNotes(newNotes);
    debouncedUpdate(newNotes);
  }, [debouncedUpdate]);

  const handleSeverityChange = async (newSeverity: string) => {
    try {
      setIsLoading(true);
      setError(null);
      await axios.patch(`/api/results/${id}`, {
        severity: newSeverity,
        notes
      });
      setSeverity(newSeverity);
      setIsEditing(false);
    } catch (err) {
      setError('Failed to update severity');
      toast.error('Failed to update severity');
    } finally {
      setIsLoading(false);
    }
  };

  const currentSeverity = severityOptions.find(s => s.value === severity) || severityOptions[0];

  return (
    <div className="bg-white rounded-lg shadow p-4 border border-gray-200">
      {/* Header with URL and Severity */}
      <div className="flex justify-between items-start mb-2">
        <div className="flex-1">
          <h3 className="font-medium text-gray-900">{moduleId}</h3>
          <p className="text-sm text-gray-500 break-all">{url}</p>
        </div>
        <div className="relative ml-4">
          {isEditing ? (
            <div className="absolute right-0 mt-2 w-48 rounded-md shadow-lg bg-white ring-1 ring-black ring-opacity-5 z-10">
              <div className="py-1">
                {severityOptions.map((option) => (
                  <button
                    key={option.value}
                    className={`w-full text-left px-4 py-2 text-sm hover:bg-gray-100 ${
                      option.value === severity ? 'bg-gray-50' : ''
                    }`}
                    onClick={() => handleSeverityChange(option.value)}
                  >
                    {option.label}
                  </button>
                ))}
              </div>
            </div>
          ) : (
            <button
              onClick={() => setIsEditing(true)}
              className={`px-3 py-1 rounded-full text-xs font-medium ${currentSeverity.color}`}
              disabled={isLoading}
            >
              {currentSeverity.label}
            </button>
          )}
        </div>
      </div>

      {/* Snippet */}
      <div className="mt-2">
        <p className="text-sm text-gray-600 font-mono bg-gray-50 p-2 rounded">
          {snippet}
        </p>
      </div>

      {/* Notes */}
      <div className="mt-4">
        <label htmlFor={`notes-${id}`} className="block text-sm font-medium text-gray-700 mb-1">
          Notes
        </label>
        <textarea
          id={`notes-${id}`}
          rows={3}
          value={notes}
          onChange={handleNotesChange}
          className={`w-full px-3 py-2 border rounded-md shadow-sm focus:ring-indigo-500 focus:border-indigo-500 ${
            error ? 'border-red-500' : 'border-gray-300'
          }`}
          placeholder="Add notes about this finding..."
          disabled={isLoading}
        />
        {error && (
          <p className="mt-1 text-sm text-red-600">{error}</p>
        )}
      </div>

      {/* Loading Indicator */}
      {isLoading && (
        <div className="mt-2 flex items-center text-sm text-gray-500">
          <svg
            className="animate-spin -ml-1 mr-2 h-4 w-4 text-gray-500"
            xmlns="http://www.w3.org/2000/svg"
            fill="none"
            viewBox="0 0 24 24"
          >
            <circle
              className="opacity-25"
              cx="12"
              cy="12"
              r="10"
              stroke="currentColor"
              strokeWidth="4"
            />
            <path
              className="opacity-75"
              fill="currentColor"
              d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"
            />
          </svg>
          Saving...
        </div>
      )}
    </div>
  );
}; 