import React, { useState } from "react"
import { useForm, Controller } from 'react-hook-form';
import { useNavigate } from 'react-router-dom';
import { toast } from 'react-hot-toast';
import axios from 'axios';
import { UseFormRegister } from "react-hook-form"

const AVAILABLE_MODULES = [
  { id: "sqli", name: "SQL Injection" },
  { id: "xss", name: "Cross-Site Scripting" },
  { id: "insecure_headers", name: "Insecure Headers" },
  { id: "open_redirect", name: "Open Redirect" },
  { id: "dir_listing", name: "Directory Listing" },
  { id: "weak_basic_auth", name: "Weak Basic Auth" },
  { id: "csrf_token", name: "CSRF Token" },
  { id: "weak_password", name: "Weak Password" },
  { id: "x_content_type", name: "X-Content-Type-Options" },
  { id: "verbose_error", name: "Verbose Error" }
];

type ScanFormData = {
  url: string;
  modules: Record<string, boolean>;
  concurrency: number;
};

export const ScanWizard = () => {
  const navigate = useNavigate();
  const { register, handleSubmit, control, formState: { errors } } = useForm<ScanFormData>({
    defaultValues: {
      url: '',
      modules: Object.fromEntries(AVAILABLE_MODULES.map(m => [m.id, true])),
      concurrency: 5
    }
  });

  const [isLoading, setIsLoading] = useState(false);

  const handleFormSubmit = async (data: ScanFormData) => {
    setIsLoading(true);
    try {
      const response = await axios.post('/api/scans', {
        url: data.url,
        modules: Object.entries(data.modules).filter(([_, enabled]) => enabled).map(([id]) => id),
        concurrency: data.concurrency
      });
      toast.success('Scan started successfully!');
      navigate(`/dashboard/${response.data.id}`);
    } catch (error) {
      toast.error('Failed to start scan. Please try again.');
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="w-full max-w-2xl mx-auto p-6">
      <h2 className="text-2xl font-bold mb-6">Start a New Scan</h2>
      <form onSubmit={handleSubmit(handleFormSubmit)} className="space-y-6">
        <div>
          <label htmlFor="url" className="block text-sm font-medium text-gray-700 mb-1">
            Target URL
          </label>
          <input
            id="url"
            type="url"
            className={`w-full px-3 py-2 border rounded-md shadow-sm focus:ring-indigo-500 focus:border-indigo-500 ${errors.url ? "border-red-500" : "border-gray-300"}`}
            placeholder="https://example.com"
            {...register("url", {
              required: "URL is required",
              pattern: {
                value: /^https?:\/\/.+/,
                message: "Please enter a valid URL starting with http:// or https://"
              }
            })}
            aria-invalid={!!errors.url}
            aria-label="Target URL"
            required
          />
          {errors.url && <p className="mt-1 text-sm text-red-600">{errors.url.message}</p>}
        </div>
        <ModuleSelector register={register} modules={AVAILABLE_MODULES} />
        <div>
          <label htmlFor="concurrency" className="block text-sm font-medium text-gray-700 mb-2">
            Concurrency: <span className="text-indigo-600">{control._formValues.concurrency}</span>
          </label>
          <Controller
            name="concurrency"
            control={control}
            render={({ field }) => (
              <input
                type="range"
                min="1"
                max="10"
                step="1"
                className="w-full h-2 bg-gray-200 rounded-lg appearance-none cursor-pointer"
                {...field}
                aria-label="Concurrency"
              />
            )}
          />
          <div className="flex justify-between text-xs text-gray-500 mt-1">
            <span>1</span>
            <span>10</span>
          </div>
        </div>
        <div>
          <button
            type="submit"
            className="w-full flex justify-center py-2 px-4 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-indigo-600 hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500"
            disabled={isLoading}
            aria-busy={isLoading}
          >
            {isLoading ? "Starting..." : "Start Scan"}
          </button>
        </div>
      </form>
    </div>
  );
};

type ModuleSelectorProps = {
  register: UseFormRegister<ScanFormData>
  modules: { id: string; name: string }[]
}

const ModuleSelector = ({ register, modules }: ModuleSelectorProps) => (
  <fieldset>
    <legend className="block text-sm font-medium text-gray-700 mb-2">Scan Modules</legend>
    <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
      {modules.map(module => (
        <label key={module.id} className="flex items-center gap-2 cursor-pointer">
          <input
            type="checkbox"
            className="h-4 w-4 text-indigo-600 focus:ring-indigo-500 border-gray-300 rounded"
            {...register(`modules.${module.id}` as const)}
            defaultChecked
            aria-checked="true"
            aria-label={module.name}
          />
          <span className="text-sm text-gray-700">{module.name}</span>
        </label>
      ))}
    </div>
  </fieldset>
)

export function ScanResults({ results }: { results: any[] }) {
  if (!results.length) return null
  return (
    <div className="max-w-2xl mx-auto mt-6">
      <h2 className="font-bold text-xl mb-2">Potential Vulnerabilities</h2>
      <ul className="space-y-2">
        {results.map((r, i) => (
          <li key={i} className="border rounded p-3 bg-gray-50">
            <div className="font-semibold">{r.module_id}</div>
            <div className="text-sm">{r.description}</div>
            <div className={`text-xs mt-1 ${r.severity === "high" ? "text-red-600" : "text-yellow-600"}`}>
              Severity: {r.severity}
            </div>
          </li>
        ))}
      </ul>
    </div>
  )
} 