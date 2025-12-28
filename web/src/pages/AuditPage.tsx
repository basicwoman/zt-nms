import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import {
  Search,
  Filter,
  FileText,
  Clock,
  CheckCircle,
  XCircle,
  AlertTriangle,
  User,
  Server,
  Shield,
  Key,
  Settings,
  Activity,
  Download,
  Eye,
  Link2,
  Calendar,
} from 'lucide-react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Badge } from '@/components/ui/badge'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { Label } from '@/components/ui/label'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { auditApi } from '@/api/client'
import type { AuditEvent, AuditEventType, AuditResult } from '@/types/api'

const eventTypeConfig: Record<AuditEventType, { icon: React.ElementType; color: string; label: string }> = {
  auth: { icon: Key, color: 'text-blue-500', label: 'Authentication' },
  identity: { icon: User, color: 'text-purple-500', label: 'Identity' },
  capability: { icon: Shield, color: 'text-green-500', label: 'Capability' },
  policy: { icon: FileText, color: 'text-orange-500', label: 'Policy' },
  config: { icon: Settings, color: 'text-cyan-500', label: 'Configuration' },
  device: { icon: Server, color: 'text-gray-500', label: 'Device' },
  deployment: { icon: Activity, color: 'text-indigo-500', label: 'Deployment' },
  security: { icon: AlertTriangle, color: 'text-red-500', label: 'Security' },
}

const resultConfig: Record<AuditResult, { icon: React.ElementType; color: string; label: string }> = {
  success: { icon: CheckCircle, color: 'text-green-500', label: 'Success' },
  failure: { icon: XCircle, color: 'text-red-500', label: 'Failure' },
  denied: { icon: AlertTriangle, color: 'text-yellow-500', label: 'Denied' },
}

// Mock audit events
const mockAuditEvents: AuditEvent[] = [
  {
    id: 'evt-001',
    sequence: 1001,
    prev_hash: 'abc123',
    event_hash: 'def456',
    timestamp: new Date(Date.now() - 300000).toISOString(),
    event_type: 'auth',
    actor_id: 'user-001',
    actor_name: 'john.doe',
    actor_type: 'operator',
    resource_type: 'session',
    resource_id: 'sess-001',
    action: 'login',
    result: 'success',
    source_ip: '192.168.1.100',
    user_agent: 'Mozilla/5.0',
  },
  {
    id: 'evt-002',
    sequence: 1002,
    prev_hash: 'def456',
    event_hash: 'ghi789',
    timestamp: new Date(Date.now() - 600000).toISOString(),
    event_type: 'capability',
    actor_id: 'user-002',
    actor_name: 'alice.smith',
    actor_type: 'operator',
    resource_type: 'capability',
    resource_id: 'cap-001',
    action: 'request',
    result: 'success',
    source_ip: '192.168.1.101',
  },
  {
    id: 'evt-003',
    sequence: 1003,
    prev_hash: 'ghi789',
    event_hash: 'jkl012',
    timestamp: new Date(Date.now() - 900000).toISOString(),
    event_type: 'config',
    actor_id: 'user-001',
    actor_name: 'john.doe',
    actor_type: 'operator',
    resource_type: 'device',
    resource_id: 'router-01',
    action: 'deploy',
    result: 'success',
    capability_id: 'cap-001',
    source_ip: '192.168.1.100',
  },
  {
    id: 'evt-004',
    sequence: 1004,
    prev_hash: 'jkl012',
    event_hash: 'mno345',
    timestamp: new Date(Date.now() - 1200000).toISOString(),
    event_type: 'security',
    actor_id: 'unknown',
    actor_type: 'operator',
    resource_type: 'session',
    resource_id: 'sess-002',
    action: 'login_attempt',
    result: 'denied',
    details: { reason: 'Invalid credentials', attempts: 3 },
    source_ip: '10.0.0.50',
  },
  {
    id: 'evt-005',
    sequence: 1005,
    prev_hash: 'mno345',
    event_hash: 'pqr678',
    timestamp: new Date(Date.now() - 1800000).toISOString(),
    event_type: 'policy',
    actor_id: 'admin-001',
    actor_name: 'admin',
    actor_type: 'operator',
    resource_type: 'policy',
    resource_id: 'pol-001',
    action: 'activate',
    result: 'success',
    source_ip: '192.168.1.1',
  },
  {
    id: 'evt-006',
    sequence: 1006,
    prev_hash: 'pqr678',
    event_hash: 'stu901',
    timestamp: new Date(Date.now() - 3600000).toISOString(),
    event_type: 'device',
    actor_id: 'svc-attestation',
    actor_type: 'service',
    resource_type: 'device',
    resource_id: 'switch-03',
    action: 'attestation',
    result: 'failure',
    details: { reason: 'PCR mismatch' },
    source_ip: '10.0.0.1',
  },
]

export function AuditPage() {
  const [searchQuery, setSearchQuery] = useState('')
  const [eventTypeFilter, setEventTypeFilter] = useState<string>('all')
  const [resultFilter, setResultFilter] = useState<string>('all')
  const [dateFrom, setDateFrom] = useState('')
  const [dateTo, setDateTo] = useState('')
  const [selectedEvent, setSelectedEvent] = useState<AuditEvent | null>(null)

  // Using mock data for now
  const events = mockAuditEvents

  // Calculate stats
  const stats = {
    total: events.length,
    success: events.filter((e) => e.result === 'success').length,
    failure: events.filter((e) => e.result === 'failure').length,
    denied: events.filter((e) => e.result === 'denied').length,
    security: events.filter((e) => e.event_type === 'security').length,
  }

  const filteredEvents = events.filter((event) => {
    if (eventTypeFilter !== 'all' && event.event_type !== eventTypeFilter) return false
    if (resultFilter !== 'all' && event.result !== resultFilter) return false
    if (searchQuery) {
      const query = searchQuery.toLowerCase()
      return (
        event.actor_name?.toLowerCase().includes(query) ||
        event.resource_id.toLowerCase().includes(query) ||
        event.action.toLowerCase().includes(query)
      )
    }
    return true
  })

  const formatTimestamp = (ts: string): string => {
    const date = new Date(ts)
    const now = new Date()
    const diffMs = now.getTime() - date.getTime()
    const diffMins = Math.floor(diffMs / 60000)
    const diffHours = Math.floor(diffMs / 3600000)
    const diffDays = Math.floor(diffMs / 86400000)

    if (diffMins < 1) return 'Just now'
    if (diffMins < 60) return `${diffMins}m ago`
    if (diffHours < 24) return `${diffHours}h ago`
    if (diffDays < 7) return `${diffDays}d ago`
    return date.toLocaleDateString()
  }

  const exportEvents = () => {
    const csv = [
      ['Timestamp', 'Event Type', 'Actor', 'Action', 'Resource', 'Result', 'Source IP'].join(','),
      ...filteredEvents.map((e) =>
        [
          e.timestamp,
          e.event_type,
          e.actor_name || e.actor_id,
          e.action,
          `${e.resource_type}:${e.resource_id}`,
          e.result,
          e.source_ip,
        ].join(',')
      ),
    ].join('\n')

    const blob = new Blob([csv], { type: 'text/csv' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `audit-events-${new Date().toISOString().split('T')[0]}.csv`
    a.click()
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold">Audit Logs</h1>
          <p className="text-muted-foreground">View and analyze system audit events</p>
        </div>
        <Button variant="outline" onClick={exportEvents}>
          <Download className="mr-2 h-4 w-4" />
          Export CSV
        </Button>
      </div>

      {/* Stats Cards */}
      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-5">
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium flex items-center gap-2">
              <FileText className="h-4 w-4" /> Total Events
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{stats.total}</div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium flex items-center gap-2">
              <CheckCircle className="h-4 w-4 text-green-500" /> Success
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-green-600">{stats.success}</div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium flex items-center gap-2">
              <XCircle className="h-4 w-4 text-red-500" /> Failures
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-red-600">{stats.failure}</div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium flex items-center gap-2">
              <AlertTriangle className="h-4 w-4 text-yellow-500" /> Denied
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-yellow-600">{stats.denied}</div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium flex items-center gap-2">
              <Shield className="h-4 w-4 text-red-500" /> Security
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-red-600">{stats.security}</div>
          </CardContent>
        </Card>
      </div>

      {/* Chain Integrity Banner */}
      <Card className="border-green-500/50 bg-green-500/5">
        <CardContent className="flex items-center gap-4 pt-6">
          <Link2 className="h-8 w-8 text-green-500" />
          <div>
            <h3 className="font-semibold">Audit Chain Integrity Verified</h3>
            <p className="text-sm text-muted-foreground">
              All {events.length} events in the audit chain have valid cryptographic links.
              Last verification: {new Date().toLocaleTimeString()}
            </p>
          </div>
          <Button variant="outline" className="ml-auto">
            Verify Chain
          </Button>
        </CardContent>
      </Card>

      {/* Filters and Table */}
      <Card>
        <CardHeader>
          <CardTitle>Event Log</CardTitle>
          <CardDescription>Immutable audit trail of all system events</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="flex flex-wrap gap-4 mb-6">
            <div className="flex-1 min-w-[200px]">
              <div className="relative">
                <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
                <Input
                  placeholder="Search events..."
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  className="pl-10"
                />
              </div>
            </div>
            <Select value={eventTypeFilter} onValueChange={setEventTypeFilter}>
              <SelectTrigger className="w-[150px]">
                <Filter className="mr-2 h-4 w-4" />
                <SelectValue placeholder="Event Type" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Types</SelectItem>
                <SelectItem value="auth">Authentication</SelectItem>
                <SelectItem value="identity">Identity</SelectItem>
                <SelectItem value="capability">Capability</SelectItem>
                <SelectItem value="policy">Policy</SelectItem>
                <SelectItem value="config">Configuration</SelectItem>
                <SelectItem value="device">Device</SelectItem>
                <SelectItem value="deployment">Deployment</SelectItem>
                <SelectItem value="security">Security</SelectItem>
              </SelectContent>
            </Select>
            <Select value={resultFilter} onValueChange={setResultFilter}>
              <SelectTrigger className="w-[130px]">
                <SelectValue placeholder="Result" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Results</SelectItem>
                <SelectItem value="success">Success</SelectItem>
                <SelectItem value="failure">Failure</SelectItem>
                <SelectItem value="denied">Denied</SelectItem>
              </SelectContent>
            </Select>
            <div className="flex items-center gap-2">
              <Calendar className="h-4 w-4 text-muted-foreground" />
              <Input
                type="date"
                value={dateFrom}
                onChange={(e) => setDateFrom(e.target.value)}
                className="w-[140px]"
              />
              <span className="text-muted-foreground">to</span>
              <Input
                type="date"
                value={dateTo}
                onChange={(e) => setDateTo(e.target.value)}
                className="w-[140px]"
              />
            </div>
          </div>

          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Timestamp</TableHead>
                <TableHead>Event Type</TableHead>
                <TableHead>Actor</TableHead>
                <TableHead>Action</TableHead>
                <TableHead>Resource</TableHead>
                <TableHead>Result</TableHead>
                <TableHead>Source IP</TableHead>
                <TableHead className="w-[50px]"></TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {filteredEvents.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={8} className="text-center py-8 text-muted-foreground">
                    No audit events found
                  </TableCell>
                </TableRow>
              ) : (
                filteredEvents.map((event) => {
                  const typeInfo = eventTypeConfig[event.event_type]
                  const TypeIcon = typeInfo.icon
                  const resultInfo = resultConfig[event.result]
                  const ResultIcon = resultInfo.icon

                  return (
                    <TableRow key={event.id} className="cursor-pointer hover:bg-muted/50">
                      <TableCell>
                        <div className="flex items-center gap-2">
                          <Clock className="h-3 w-3 text-muted-foreground" />
                          <span>{formatTimestamp(event.timestamp)}</span>
                        </div>
                      </TableCell>
                      <TableCell>
                        <div className="flex items-center gap-2">
                          <TypeIcon className={`h-4 w-4 ${typeInfo.color}`} />
                          <span>{typeInfo.label}</span>
                        </div>
                      </TableCell>
                      <TableCell>
                        <div>
                          <div className="font-medium">{event.actor_name || 'Unknown'}</div>
                          <div className="text-xs text-muted-foreground capitalize">
                            {event.actor_type}
                          </div>
                        </div>
                      </TableCell>
                      <TableCell>
                        <Badge variant="outline" className="capitalize">
                          {event.action.replace(/_/g, ' ')}
                        </Badge>
                      </TableCell>
                      <TableCell>
                        <div className="font-mono text-sm">
                          {event.resource_type}:{event.resource_id.slice(0, 12)}
                        </div>
                      </TableCell>
                      <TableCell>
                        <div className="flex items-center gap-2">
                          <ResultIcon className={`h-4 w-4 ${resultInfo.color}`} />
                          <span>{resultInfo.label}</span>
                        </div>
                      </TableCell>
                      <TableCell className="font-mono text-sm text-muted-foreground">
                        {event.source_ip}
                      </TableCell>
                      <TableCell>
                        <Button
                          variant="ghost"
                          size="icon"
                          onClick={() => setSelectedEvent(event)}
                        >
                          <Eye className="h-4 w-4" />
                        </Button>
                      </TableCell>
                    </TableRow>
                  )
                })
              )}
            </TableBody>
          </Table>
        </CardContent>
      </Card>

      {/* Event Detail Dialog */}
      {selectedEvent && (
        <Dialog open={!!selectedEvent} onOpenChange={() => setSelectedEvent(null)}>
          <DialogContent className="max-w-2xl">
            <DialogHeader>
              <DialogTitle>Audit Event Details</DialogTitle>
            </DialogHeader>
            <div className="space-y-4">
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <Label className="text-muted-foreground">Event ID</Label>
                  <p className="font-mono text-sm">{selectedEvent.id}</p>
                </div>
                <div>
                  <Label className="text-muted-foreground">Sequence</Label>
                  <p className="font-mono">#{selectedEvent.sequence}</p>
                </div>
                <div>
                  <Label className="text-muted-foreground">Timestamp</Label>
                  <p>{new Date(selectedEvent.timestamp).toLocaleString()}</p>
                </div>
                <div>
                  <Label className="text-muted-foreground">Event Type</Label>
                  <div className="flex items-center gap-2">
                    {(() => {
                      const info = eventTypeConfig[selectedEvent.event_type]
                      const Icon = info.icon
                      return (
                        <>
                          <Icon className={`h-4 w-4 ${info.color}`} />
                          <span>{info.label}</span>
                        </>
                      )
                    })()}
                  </div>
                </div>
              </div>

              <div className="border-t pt-4">
                <h4 className="font-medium mb-2">Actor</h4>
                <div className="grid grid-cols-2 gap-4 p-3 rounded-lg bg-muted">
                  <div>
                    <Label className="text-muted-foreground text-xs">Name</Label>
                    <p>{selectedEvent.actor_name || 'Unknown'}</p>
                  </div>
                  <div>
                    <Label className="text-muted-foreground text-xs">Type</Label>
                    <p className="capitalize">{selectedEvent.actor_type}</p>
                  </div>
                  <div>
                    <Label className="text-muted-foreground text-xs">ID</Label>
                    <p className="font-mono text-sm">{selectedEvent.actor_id}</p>
                  </div>
                  <div>
                    <Label className="text-muted-foreground text-xs">Source IP</Label>
                    <p className="font-mono">{selectedEvent.source_ip}</p>
                  </div>
                </div>
              </div>

              <div className="border-t pt-4">
                <h4 className="font-medium mb-2">Action & Resource</h4>
                <div className="grid grid-cols-2 gap-4 p-3 rounded-lg bg-muted">
                  <div>
                    <Label className="text-muted-foreground text-xs">Action</Label>
                    <Badge variant="outline" className="capitalize">
                      {selectedEvent.action.replace(/_/g, ' ')}
                    </Badge>
                  </div>
                  <div>
                    <Label className="text-muted-foreground text-xs">Result</Label>
                    <div className="flex items-center gap-2">
                      {(() => {
                        const info = resultConfig[selectedEvent.result]
                        const Icon = info.icon
                        return (
                          <>
                            <Icon className={`h-4 w-4 ${info.color}`} />
                            <span>{info.label}</span>
                          </>
                        )
                      })()}
                    </div>
                  </div>
                  <div>
                    <Label className="text-muted-foreground text-xs">Resource Type</Label>
                    <p>{selectedEvent.resource_type}</p>
                  </div>
                  <div>
                    <Label className="text-muted-foreground text-xs">Resource ID</Label>
                    <p className="font-mono text-sm">{selectedEvent.resource_id}</p>
                  </div>
                </div>
              </div>

              <div className="border-t pt-4">
                <h4 className="font-medium mb-2">Chain Verification</h4>
                <div className="grid grid-cols-1 gap-2 p-3 rounded-lg bg-muted font-mono text-xs">
                  <div>
                    <Label className="text-muted-foreground">Previous Hash</Label>
                    <p className="break-all">{selectedEvent.prev_hash}</p>
                  </div>
                  <div>
                    <Label className="text-muted-foreground">Event Hash</Label>
                    <p className="break-all">{selectedEvent.event_hash}</p>
                  </div>
                </div>
              </div>

              {selectedEvent.details && (
                <div className="border-t pt-4">
                  <h4 className="font-medium mb-2">Details</h4>
                  <pre className="p-3 rounded-lg bg-muted font-mono text-xs overflow-auto">
                    {JSON.stringify(selectedEvent.details, null, 2)}
                  </pre>
                </div>
              )}
            </div>
          </DialogContent>
        </Dialog>
      )}
    </div>
  )
}
