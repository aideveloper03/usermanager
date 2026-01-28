'use client';

import { useState, useEffect } from 'react';
import { useUser, useAuth, UserButton } from '@clerk/nextjs';
import Link from 'next/link';
import {
  Zap,
  Play,
  Clock,
  CheckCircle,
  XCircle,
  Loader2,
  Plus,
  RefreshCw,
  CreditCard,
  Activity,
} from 'lucide-react';

const GATEWAY_URL = process.env.NEXT_PUBLIC_GATEWAY_URL || 'http://localhost:8000';

interface Workflow {
  id: string;
  name: string;
  description: string;
  credits_per_execution: number;
  is_active: boolean;
}

interface ExecutionResult {
  success: boolean;
  execution_id?: string;
  status?: string;
  data?: any;
  credits_used?: number;
  credits_remaining?: number;
  execution_time_ms?: number;
  error?: string;
}

interface Organization {
  id: string;
  name: string;
  credits: number;
  plan_type: string;
}

export default function DashboardPage() {
  const { user, isLoaded: userLoaded } = useUser();
  const { getToken } = useAuth();
  
  const [workflows, setWorkflows] = useState<Workflow[]>([]);
  const [organization, setOrganization] = useState<Organization | null>(null);
  const [loading, setLoading] = useState(true);
  const [executing, setExecuting] = useState<string | null>(null);
  const [results, setResults] = useState<Record<string, ExecutionResult>>({});
  const [error, setError] = useState<string | null>(null);
  
  // Workflow execution form state
  const [selectedWorkflow, setSelectedWorkflow] = useState<string | null>(null);
  const [inputData, setInputData] = useState('{\n  "message": "Hello from the gateway!"\n}');
  
  // Fetch organization and workflows
  useEffect(() => {
    if (userLoaded && user) {
      fetchData();
    }
  }, [userLoaded, user]);
  
  async function fetchData() {
    setLoading(true);
    setError(null);
    
    try {
      const token = await getToken();
      
      // Fetch organization
      const orgResponse = await fetch(`${GATEWAY_URL}/api/v1/organizations`, {
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json',
        },
      });
      
      if (orgResponse.ok) {
        const orgData = await orgResponse.json();
        setOrganization(orgData[0] || null);
      }
      
      // Fetch workflows
      const wfResponse = await fetch(`${GATEWAY_URL}/api/v1/workflows`, {
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json',
        },
      });
      
      if (wfResponse.ok) {
        const wfData = await wfResponse.json();
        setWorkflows(wfData || []);
      }
    } catch (err) {
      console.error('Failed to fetch data:', err);
      setError('Failed to connect to the gateway. Make sure the server is running.');
    } finally {
      setLoading(false);
    }
  }
  
  async function executeWorkflow(workflowId: string) {
    setExecuting(workflowId);
    setResults((prev) => ({ ...prev, [workflowId]: { success: false } }));
    
    try {
      const token = await getToken();
      let data;
      
      try {
        data = JSON.parse(inputData);
      } catch {
        data = { input: inputData };
      }
      
      const response = await fetch(`${GATEWAY_URL}/api/v1/execute`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          workflow_id: workflowId,
          data: data,
          metadata: {
            source: 'web-dashboard',
            user_id: user?.id,
          },
        }),
      });
      
      const result = await response.json();
      
      if (response.ok) {
        setResults((prev) => ({
          ...prev,
          [workflowId]: {
            success: true,
            ...result,
          },
        }));
        
        // Refresh organization to update credits
        fetchData();
      } else {
        setResults((prev) => ({
          ...prev,
          [workflowId]: {
            success: false,
            error: result.detail || result.message || 'Execution failed',
          },
        }));
      }
    } catch (err) {
      setResults((prev) => ({
        ...prev,
        [workflowId]: {
          success: false,
          error: err instanceof Error ? err.message : 'Unknown error',
        },
      }));
    } finally {
      setExecuting(null);
    }
  }
  
  if (!userLoaded || loading) {
    return (
      <div className="flex min-h-screen items-center justify-center">
        <Loader2 className="h-8 w-8 animate-spin text-primary" />
      </div>
    );
  }
  
  return (
    <div className="min-h-screen bg-gray-50 dark:bg-gray-900">
      {/* Header */}
      <header className="sticky top-0 z-50 w-full border-b bg-white dark:bg-gray-800 shadow-sm">
        <div className="container flex h-16 items-center justify-between px-4 md:px-6">
          <div className="flex items-center gap-4">
            <Link href="/" className="flex items-center space-x-2">
              <Zap className="h-6 w-6 text-primary" />
              <span className="font-bold text-xl">N8N Gateway</span>
            </Link>
            <span className="text-sm text-gray-500 dark:text-gray-400">
              / Dashboard
            </span>
          </div>
          <div className="flex items-center gap-4">
            <button
              onClick={fetchData}
              className="flex items-center gap-2 px-3 py-2 text-sm text-gray-600 hover:text-gray-900 dark:text-gray-300 dark:hover:text-white"
            >
              <RefreshCw className="h-4 w-4" />
              Refresh
            </button>
            <UserButton afterSignOutUrl="/" />
          </div>
        </div>
      </header>
      
      <main className="container px-4 md:px-6 py-8">
        {error && (
          <div className="mb-6 rounded-lg bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 p-4 text-red-700 dark:text-red-400">
            {error}
          </div>
        )}
        
        {/* Stats Cards */}
        <div className="grid gap-4 md:grid-cols-3 mb-8">
          <StatsCard
            title="Credits Balance"
            value={organization?.credits?.toString() || '0'}
            icon={<CreditCard className="h-5 w-5" />}
            description="Available credits"
          />
          <StatsCard
            title="Active Workflows"
            value={workflows.filter((w) => w.is_active).length.toString()}
            icon={<Activity className="h-5 w-5" />}
            description="Ready to execute"
          />
          <StatsCard
            title="Plan"
            value={organization?.plan_type || 'Free'}
            icon={<Zap className="h-5 w-5" />}
            description={organization?.name || 'No organization'}
          />
        </div>
        
        {/* Workflow Execution Panel */}
        <div className="grid gap-6 lg:grid-cols-2">
          {/* Workflow List */}
          <div className="rounded-lg border bg-white dark:bg-gray-800 shadow-sm">
            <div className="flex items-center justify-between border-b px-6 py-4">
              <h2 className="text-lg font-semibold text-gray-900 dark:text-white">
                Your Workflows
              </h2>
              <button className="flex items-center gap-2 px-3 py-2 text-sm bg-primary text-primary-foreground rounded-md hover:bg-primary/90">
                <Plus className="h-4 w-4" />
                Add Workflow
              </button>
            </div>
            <div className="divide-y">
              {workflows.length === 0 ? (
                <div className="p-6 text-center text-gray-500 dark:text-gray-400">
                  No workflows found. Create your first workflow to get started.
                </div>
              ) : (
                workflows.map((workflow) => (
                  <WorkflowItem
                    key={workflow.id}
                    workflow={workflow}
                    selected={selectedWorkflow === workflow.id}
                    executing={executing === workflow.id}
                    result={results[workflow.id]}
                    onSelect={() => setSelectedWorkflow(workflow.id)}
                    onExecute={() => executeWorkflow(workflow.id)}
                  />
                ))
              )}
            </div>
          </div>
          
          {/* Execution Input */}
          <div className="rounded-lg border bg-white dark:bg-gray-800 shadow-sm">
            <div className="border-b px-6 py-4">
              <h2 className="text-lg font-semibold text-gray-900 dark:text-white">
                Execution Input
              </h2>
              <p className="text-sm text-gray-500 dark:text-gray-400">
                JSON data to send to the workflow
              </p>
            </div>
            <div className="p-6">
              <textarea
                value={inputData}
                onChange={(e) => setInputData(e.target.value)}
                className="w-full h-64 p-4 font-mono text-sm bg-gray-50 dark:bg-gray-900 border rounded-lg focus:ring-2 focus:ring-primary focus:border-transparent"
                placeholder='{"key": "value"}'
              />
              <div className="mt-4 flex items-center justify-between">
                <p className="text-sm text-gray-500 dark:text-gray-400">
                  {selectedWorkflow
                    ? `Selected: ${workflows.find((w) => w.id === selectedWorkflow)?.name}`
                    : 'Select a workflow to execute'}
                </p>
                <button
                  onClick={() => selectedWorkflow && executeWorkflow(selectedWorkflow)}
                  disabled={!selectedWorkflow || executing !== null}
                  className="flex items-center gap-2 px-4 py-2 bg-primary text-primary-foreground rounded-md hover:bg-primary/90 disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  {executing ? (
                    <Loader2 className="h-4 w-4 animate-spin" />
                  ) : (
                    <Play className="h-4 w-4" />
                  )}
                  Execute
                </button>
              </div>
            </div>
            
            {/* Latest Result */}
            {selectedWorkflow && results[selectedWorkflow] && (
              <div className="border-t px-6 py-4">
                <h3 className="text-sm font-medium text-gray-900 dark:text-white mb-2">
                  Latest Result
                </h3>
                <div
                  className={`p-4 rounded-lg ${
                    results[selectedWorkflow].success
                      ? 'bg-green-50 dark:bg-green-900/20 border border-green-200 dark:border-green-800'
                      : 'bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800'
                  }`}
                >
                  <div className="flex items-center gap-2 mb-2">
                    {results[selectedWorkflow].success ? (
                      <CheckCircle className="h-4 w-4 text-green-600" />
                    ) : (
                      <XCircle className="h-4 w-4 text-red-600" />
                    )}
                    <span
                      className={`text-sm font-medium ${
                        results[selectedWorkflow].success
                          ? 'text-green-700 dark:text-green-400'
                          : 'text-red-700 dark:text-red-400'
                      }`}
                    >
                      {results[selectedWorkflow].success ? 'Success' : 'Failed'}
                    </span>
                    {results[selectedWorkflow].execution_time_ms && (
                      <span className="text-xs text-gray-500">
                        ({results[selectedWorkflow].execution_time_ms}ms)
                      </span>
                    )}
                  </div>
                  <pre className="text-xs overflow-auto max-h-32">
                    {JSON.stringify(
                      results[selectedWorkflow].data ||
                        results[selectedWorkflow].error ||
                        results[selectedWorkflow],
                      null,
                      2
                    )}
                  </pre>
                </div>
              </div>
            )}
          </div>
        </div>
      </main>
    </div>
  );
}

function StatsCard({
  title,
  value,
  icon,
  description,
}: {
  title: string;
  value: string;
  icon: React.ReactNode;
  description: string;
}) {
  return (
    <div className="rounded-lg border bg-white dark:bg-gray-800 p-6 shadow-sm">
      <div className="flex items-center justify-between">
        <p className="text-sm font-medium text-gray-500 dark:text-gray-400">
          {title}
        </p>
        <div className="text-primary">{icon}</div>
      </div>
      <p className="mt-2 text-3xl font-bold text-gray-900 dark:text-white">
        {value}
      </p>
      <p className="text-sm text-gray-500 dark:text-gray-400">{description}</p>
    </div>
  );
}

function WorkflowItem({
  workflow,
  selected,
  executing,
  result,
  onSelect,
  onExecute,
}: {
  workflow: Workflow;
  selected: boolean;
  executing: boolean;
  result?: ExecutionResult;
  onSelect: () => void;
  onExecute: () => void;
}) {
  return (
    <div
      className={`flex items-center justify-between px-6 py-4 cursor-pointer transition-colors ${
        selected
          ? 'bg-primary/5 border-l-4 border-l-primary'
          : 'hover:bg-gray-50 dark:hover:bg-gray-700/50'
      }`}
      onClick={onSelect}
    >
      <div className="flex-1">
        <div className="flex items-center gap-2">
          <h3 className="font-medium text-gray-900 dark:text-white">
            {workflow.name}
          </h3>
          {workflow.is_active ? (
            <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-400">
              Active
            </span>
          ) : (
            <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-400">
              Inactive
            </span>
          )}
        </div>
        <p className="text-sm text-gray-500 dark:text-gray-400 mt-1">
          {workflow.description || 'No description'}
        </p>
        <div className="flex items-center gap-4 mt-2 text-xs text-gray-500 dark:text-gray-400">
          <span className="flex items-center gap-1">
            <CreditCard className="h-3 w-3" />
            {workflow.credits_per_execution} credits
          </span>
          {result && (
            <span className="flex items-center gap-1">
              {result.success ? (
                <CheckCircle className="h-3 w-3 text-green-500" />
              ) : (
                <XCircle className="h-3 w-3 text-red-500" />
              )}
              {result.success ? 'Last run: Success' : 'Last run: Failed'}
            </span>
          )}
        </div>
      </div>
      <button
        onClick={(e) => {
          e.stopPropagation();
          onExecute();
        }}
        disabled={executing || !workflow.is_active}
        className="ml-4 flex items-center gap-2 px-3 py-2 text-sm bg-primary/10 text-primary rounded-md hover:bg-primary/20 disabled:opacity-50 disabled:cursor-not-allowed"
      >
        {executing ? (
          <Loader2 className="h-4 w-4 animate-spin" />
        ) : (
          <Play className="h-4 w-4" />
        )}
        Run
      </button>
    </div>
  );
}
