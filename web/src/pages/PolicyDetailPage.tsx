import { useState } from 'react'
import { useParams, Link, useNavigate } from 'react-router-dom'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import {
  ArrowLeft,
  Shield,
  FileText,
  Clock,
  CheckCircle,
  XCircle,
  AlertTriangle,
  MoreHorizontal,
  Trash2,
  Edit,
  Copy,
  Play,
  Pause,
  History,
  GitBranch,
  Code,
} from 'lucide-react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
  DropdownMenuSeparator,
} from '@/components/ui/dropdown-menu'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Label } from '@/components/ui/label'
import { Input } from '@/components/ui/input'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'
import { policiesApi } from '@/api/client'
import type { Policy, PolicyStatus, PolicyType, PolicyRule, PolicyEffect } from '@/types/api'

const statusConfig: Record<PolicyStatus, { color: string; bgColor: string; label: string }> = {
  draft: { color: 'text-gray-500', bgColor: 'bg-gray-500', label: 'Draft' },
  active: { color: 'text-green-500', bgColor: 'bg-green-500', label: 'Active' },
  deprecated: { color: 'text-yellow-500', bgColor: 'bg-yellow-500', label: 'Deprecated' },
  archived: { color: 'text-red-500', bgColor: 'bg-red-500', label: 'Archived' },
}

const effectColors: Record<PolicyEffect, string> = {
  allow: 'bg-green-500',
  deny: 'bg-red-500',
  step_up: 'bg-yellow-500',
}

// Mock data
const mockPolicy: Policy = {
  id: 'pol-001',
  name: 'network-admin-access',
  version: 3,
  description: 'Access policy for network administrators to manage core infrastructure devices',
  type: 'access',
  status: 'active',
  definition: {
    rules: [
      {
        name: 'allow-read-all-devices',
        subjects: { groups: ['network-admins'] },
        resources: { type: 'device', pattern: '*' },
        actions: ['read', 'get-config'],
        effect: 'allow',
      },
      {
        name: 'allow-configure-non-critical',
        subjects: { groups: ['network-admins'], clearance_level: { gte: 2 } },
        resources: { type: 'device', criticality: { not: 'critical' } },
        actions: ['configure', 'edit-config'],
        conditions: [{ time_of_day: { between: ['06:00', '22:00'] } }],
        effect: 'allow',
        obligations: [
          { type: 'log', params: { level: 'info' } },
        ],
      },
      {
        name: 'require-approval-critical',
        subjects: { groups: ['network-admins'] },
        resources: { type: 'device', criticality: 'critical' },
        actions: ['configure', 'edit-config'],
        effect: 'step_up',
        obligations: [
          { type: 'require_approval', params: { approvers: ['security-team'], quorum: 1 } },
          { type: 'record_session', params: {} },
        ],
      },
      {
        name: 'deny-delete-all',
        subjects: { groups: ['network-admins'] },
        resources: { type: 'device', pattern: '*' },
        actions: ['delete', 'factory-reset'],
        effect: 'deny',
      },
    ],
  },
  effective_from: new Date(Date.now() - 30 * 86400000).toISOString(),
  created_at: new Date(Date.now() - 60 * 86400000).toISOString(),
  created_by: 'security-admin',
  approved_by: 'ciso',
  approval_signature: 'sig:ed25519:...',
}

const mockVersionHistory = [
  { version: 3, created_at: new Date(Date.now() - 7 * 86400000).toISOString(), created_by: 'security-admin', changes: 'Added step-up for critical devices' },
  { version: 2, created_at: new Date(Date.now() - 30 * 86400000).toISOString(), created_by: 'security-admin', changes: 'Added time restrictions' },
  { version: 1, created_at: new Date(Date.now() - 60 * 86400000).toISOString(), created_by: 'security-admin', changes: 'Initial version' },
]

const mockEvaluationStats = {
  total: 15420,
  allowed: 15350,
  denied: 47,
  stepUp: 23,
}

export function PolicyDetailPage() {
  const { id } = useParams<{ id: string }>()
  const navigate = useNavigate()
  const queryClient = useQueryClient()
  const [isTestDialogOpen, setIsTestDialogOpen] = useState(false)
  const [testInput, setTestInput] = useState({
    subject_id: '',
    resource_type: 'device',
    resource_id: '',
    action: '',
  })

  // Using mock data
  const policy = mockPolicy
  const versionHistory = mockVersionHistory
  const evaluationStats = mockEvaluationStats

  const activateMutation = useMutation({
    mutationFn: () => policiesApi.activate(id!),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['policies'] })
    },
  })

  const deleteMutation = useMutation({
    mutationFn: () => policiesApi.delete(id!),
    onSuccess: () => {
      navigate('/policies')
    },
  })

  const testMutation = useMutation({
    mutationFn: () => policiesApi.evaluate(testInput),
    onSuccess: (result) => {
      alert(`Decision: ${result.decision}\nMatched rules: ${result.matched_rules.join(', ')}`)
    },
  })

  const statusInfo = statusConfig[policy.status]

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-4">
          <Button variant="ghost" size="icon" asChild>
            <Link to="/policies">
              <ArrowLeft className="h-4 w-4" />
            </Link>
          </Button>
          <div>
            <div className="flex items-center gap-3">
              <Shield className="h-8 w-8" />
              <h1 className="text-3xl font-bold">{policy.name}</h1>
              <Badge className={`${statusInfo.bgColor} text-white`}>{statusInfo.label}</Badge>
              <Badge variant="outline">v{policy.version}</Badge>
            </div>
            <p className="text-muted-foreground mt-1">{policy.description}</p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <Button variant="outline" onClick={() => setIsTestDialogOpen(true)}>
            <Play className="mr-2 h-4 w-4" />
            Test Policy
          </Button>
          {policy.status === 'draft' && (
            <Button onClick={() => activateMutation.mutate()}>
              <CheckCircle className="mr-2 h-4 w-4" />
              Activate
            </Button>
          )}
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button variant="outline" size="icon">
                <MoreHorizontal className="h-4 w-4" />
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end">
              <DropdownMenuItem>
                <Edit className="mr-2 h-4 w-4" />
                Edit Policy
              </DropdownMenuItem>
              <DropdownMenuItem>
                <Copy className="mr-2 h-4 w-4" />
                Duplicate
              </DropdownMenuItem>
              <DropdownMenuItem>
                <History className="mr-2 h-4 w-4" />
                View History
              </DropdownMenuItem>
              <DropdownMenuSeparator />
              {policy.status === 'active' && (
                <DropdownMenuItem className="text-yellow-600">
                  <Pause className="mr-2 h-4 w-4" />
                  Deprecate
                </DropdownMenuItem>
              )}
              <DropdownMenuItem
                onClick={() => {
                  if (confirm('Are you sure you want to delete this policy?')) {
                    deleteMutation.mutate()
                  }
                }}
                className="text-red-600"
              >
                <Trash2 className="mr-2 h-4 w-4" />
                Delete Policy
              </DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>
        </div>
      </div>

      {/* Stats Cards */}
      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-5">
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium">Type</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-xl font-bold capitalize">{policy.type}</div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium">Total Evaluations</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{evaluationStats.total.toLocaleString()}</div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium flex items-center gap-2">
              <CheckCircle className="h-4 w-4 text-green-500" /> Allowed
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-green-600">{evaluationStats.allowed.toLocaleString()}</div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium flex items-center gap-2">
              <XCircle className="h-4 w-4 text-red-500" /> Denied
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-red-600">{evaluationStats.denied}</div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium flex items-center gap-2">
              <AlertTriangle className="h-4 w-4 text-yellow-500" /> Step-Up
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-yellow-600">{evaluationStats.stepUp}</div>
          </CardContent>
        </Card>
      </div>

      {/* Tabs */}
      <Tabs defaultValue="rules" className="space-y-4">
        <TabsList>
          <TabsTrigger value="rules">Rules</TabsTrigger>
          <TabsTrigger value="details">Details</TabsTrigger>
          <TabsTrigger value="history">Version History</TabsTrigger>
          <TabsTrigger value="json">JSON View</TabsTrigger>
        </TabsList>

        <TabsContent value="rules" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>Policy Rules</CardTitle>
              <CardDescription>
                {policy.definition?.rules?.length || 0} rules defining access control logic
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                {(policy.definition?.rules || []).map((rule: PolicyRule, index: number) => (
                  <RuleCard key={index} rule={rule} index={index} />
                ))}
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="details" className="space-y-4">
          <div className="grid gap-4 md:grid-cols-2">
            <Card>
              <CardHeader>
                <CardTitle>Policy Information</CardTitle>
              </CardHeader>
              <CardContent className="space-y-3">
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Policy ID</span>
                  <span className="font-mono">{policy.id}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Version</span>
                  <span className="font-medium">v{policy.version}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Type</span>
                  <span className="font-medium capitalize">{policy.type}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Status</span>
                  <Badge className={`${statusInfo.bgColor} text-white`}>{statusInfo.label}</Badge>
                </div>
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Rules Count</span>
                  <span className="font-medium">{policy.definition?.rules?.length || 0}</span>
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle>Lifecycle</CardTitle>
              </CardHeader>
              <CardContent className="space-y-3">
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Created By</span>
                  <span className="font-medium">{policy.created_by}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Created At</span>
                  <span>{new Date(policy.created_at).toLocaleDateString()}</span>
                </div>
                {policy.approved_by && (
                  <div className="flex justify-between">
                    <span className="text-muted-foreground">Approved By</span>
                    <span className="font-medium">{policy.approved_by}</span>
                  </div>
                )}
                {policy.effective_from && (
                  <div className="flex justify-between">
                    <span className="text-muted-foreground">Effective From</span>
                    <span>{new Date(policy.effective_from).toLocaleDateString()}</span>
                  </div>
                )}
                {policy.effective_until && (
                  <div className="flex justify-between">
                    <span className="text-muted-foreground">Effective Until</span>
                    <span>{new Date(policy.effective_until).toLocaleDateString()}</span>
                  </div>
                )}
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        <TabsContent value="history" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>Version History</CardTitle>
              <CardDescription>Track changes across policy versions</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                {versionHistory.map((version, i) => (
                  <div
                    key={version.version}
                    className="flex items-start gap-4 p-4 rounded-lg border"
                  >
                    <div className="flex flex-col items-center">
                      <div className={`p-2 rounded-full ${i === 0 ? 'bg-primary text-primary-foreground' : 'bg-muted'}`}>
                        <GitBranch className="h-4 w-4" />
                      </div>
                      {i < versionHistory.length - 1 && (
                        <div className="w-px h-full bg-border mt-2" />
                      )}
                    </div>
                    <div className="flex-1">
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-2">
                          <span className="font-medium">Version {version.version}</span>
                          {i === 0 && <Badge>Current</Badge>}
                        </div>
                        <Button variant="ghost" size="sm">
                          View
                        </Button>
                      </div>
                      <p className="text-sm text-muted-foreground mt-1">{version.changes}</p>
                      <div className="flex items-center gap-4 mt-2 text-xs text-muted-foreground">
                        <span>By {version.created_by}</span>
                        <span>{new Date(version.created_at).toLocaleString()}</span>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="json" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Code className="h-5 w-5" />
                Policy Definition (JSON)
              </CardTitle>
            </CardHeader>
            <CardContent>
              <pre className="p-4 rounded-lg bg-muted font-mono text-sm overflow-auto max-h-[600px]">
                {JSON.stringify(policy, null, 2)}
              </pre>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>

      {/* Test Policy Dialog */}
      <Dialog open={isTestDialogOpen} onOpenChange={setIsTestDialogOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Test Policy Evaluation</DialogTitle>
            <DialogDescription>
              Simulate a policy evaluation to see the decision
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4 py-4">
            <div className="space-y-2">
              <Label>Subject ID</Label>
              <Input
                value={testInput.subject_id}
                onChange={(e) => setTestInput({ ...testInput, subject_id: e.target.value })}
                placeholder="user-001"
              />
            </div>
            <div className="grid grid-cols-2 gap-4">
              <div className="space-y-2">
                <Label>Resource Type</Label>
                <Input
                  value={testInput.resource_type}
                  onChange={(e) => setTestInput({ ...testInput, resource_type: e.target.value })}
                  placeholder="device"
                />
              </div>
              <div className="space-y-2">
                <Label>Resource ID</Label>
                <Input
                  value={testInput.resource_id}
                  onChange={(e) => setTestInput({ ...testInput, resource_id: e.target.value })}
                  placeholder="router-01"
                />
              </div>
            </div>
            <div className="space-y-2">
              <Label>Action</Label>
              <Input
                value={testInput.action}
                onChange={(e) => setTestInput({ ...testInput, action: e.target.value })}
                placeholder="configure"
              />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setIsTestDialogOpen(false)}>
              Cancel
            </Button>
            <Button onClick={() => testMutation.mutate()} disabled={testMutation.isPending}>
              {testMutation.isPending ? 'Evaluating...' : 'Evaluate'}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  )
}

function RuleCard({ rule, index }: { rule: PolicyRule; index: number }) {
  return (
    <div className="p-4 rounded-lg border">
      <div className="flex items-center justify-between mb-3">
        <div className="flex items-center gap-2">
          <span className="text-muted-foreground text-sm">#{index + 1}</span>
          <span className="font-medium">{rule.name}</span>
        </div>
        <Badge className={`${effectColors[rule.effect]} text-white`}>
          {rule.effect.toUpperCase()}
        </Badge>
      </div>

      <div className="grid gap-3 md:grid-cols-3 text-sm">
        <div>
          <Label className="text-xs text-muted-foreground">Subjects</Label>
          <pre className="mt-1 p-2 rounded bg-muted text-xs overflow-auto">
            {JSON.stringify(rule.subjects, null, 2)}
          </pre>
        </div>
        <div>
          <Label className="text-xs text-muted-foreground">Resources</Label>
          <pre className="mt-1 p-2 rounded bg-muted text-xs overflow-auto">
            {JSON.stringify(rule.resources, null, 2)}
          </pre>
        </div>
        <div>
          <Label className="text-xs text-muted-foreground">Actions</Label>
          <div className="mt-1 flex flex-wrap gap-1">
            {rule.actions.map((action) => (
              <Badge key={action} variant="secondary" className="text-xs">
                {action}
              </Badge>
            ))}
          </div>
        </div>
      </div>

      {rule.conditions && (
        <div className="mt-3">
          <Label className="text-xs text-muted-foreground">Conditions</Label>
          <pre className="mt-1 p-2 rounded bg-muted text-xs overflow-auto">
            {JSON.stringify(rule.conditions, null, 2)}
          </pre>
        </div>
      )}

      {rule.obligations && rule.obligations.length > 0 && (
        <div className="mt-3">
          <Label className="text-xs text-muted-foreground">Obligations</Label>
          <div className="mt-1 flex flex-wrap gap-1">
            {rule.obligations.map((obl, i) => (
              <Badge key={i} variant="outline" className="text-xs">
                {obl.type}
              </Badge>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}
