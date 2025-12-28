import { useQuery } from '@tanstack/react-query'
import { useCallback, useRef, useEffect, useState } from 'react'
import {
  Network,
  Server,
  Shield,
  AlertTriangle,
  ZoomIn,
  ZoomOut,
  Maximize2,
  RefreshCw,
  Wifi,
  WifiOff,
} from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'
import { topologyApi } from '@/api/client'
import { useTranslation } from '@/i18n/useTranslation'

interface TopologyNode {
  id: string
  type: string
  vendor: string
  model: string
  x: number
  y: number
  status: string
  ip: string
}

interface TopologyLink {
  source: string
  target: string
  type: string
  status: string
  bandwidth: string
}

interface VLAN {
  id: number
  name: string
  subnet: string
  gateway: string
}

function NodeIcon({ type, status }: { type: string; status: string }) {
  const iconClass = `h-8 w-8 ${status === 'online' ? 'text-green-500' : status === 'degraded' ? 'text-yellow-500' : 'text-red-500'}`

  switch (type) {
    case 'router':
      return <Network className={iconClass} />
    case 'switch':
      return <Server className={iconClass} />
    case 'firewall':
      return <Shield className={iconClass} />
    default:
      return <Server className={iconClass} />
  }
}

function TopologyCanvas({ nodes, links }: { nodes: TopologyNode[]; links: TopologyLink[] }) {
  const canvasRef = useRef<HTMLCanvasElement>(null)
  const [scale, setScale] = useState(1)
  const [offset, setOffset] = useState({ x: 50, y: 50 })
  const [selectedNode, setSelectedNode] = useState<TopologyNode | null>(null)

  const draw = useCallback(() => {
    const canvas = canvasRef.current
    if (!canvas) return
    const ctx = canvas.getContext('2d')
    if (!ctx) return

    const rect = canvas.getBoundingClientRect()
    canvas.width = rect.width
    canvas.height = rect.height

    ctx.clearRect(0, 0, canvas.width, canvas.height)
    ctx.save()
    ctx.translate(offset.x, offset.y)
    ctx.scale(scale, scale)

    // Draw links
    links.forEach((link) => {
      const sourceNode = nodes.find((n) => n.id === link.source)
      const targetNode = nodes.find((n) => n.id === link.target)
      if (!sourceNode || !targetNode) return

      ctx.beginPath()
      ctx.moveTo(sourceNode.x, sourceNode.y)
      ctx.lineTo(targetNode.x, targetNode.y)
      ctx.strokeStyle = link.status === 'up' ? '#22c55e' : link.status === 'degraded' ? '#f59e0b' : '#ef4444'
      ctx.lineWidth = link.type === 'trunk' ? 3 : 2
      if (link.type === 'trunk') {
        ctx.setLineDash([5, 3])
      } else {
        ctx.setLineDash([])
      }
      ctx.stroke()
      ctx.setLineDash([])

      // Draw bandwidth label
      const midX = (sourceNode.x + targetNode.x) / 2
      const midY = (sourceNode.y + targetNode.y) / 2
      ctx.fillStyle = '#6b7280'
      ctx.font = '10px system-ui'
      ctx.fillText(link.bandwidth, midX + 5, midY - 5)
    })

    // Draw nodes
    nodes.forEach((node) => {
      const isSelected = selectedNode?.id === node.id

      // Node background
      ctx.beginPath()
      ctx.arc(node.x, node.y, isSelected ? 30 : 25, 0, 2 * Math.PI)
      ctx.fillStyle = node.status === 'online' ? '#dcfce7' : node.status === 'degraded' ? '#fef3c7' : '#fee2e2'
      ctx.fill()
      ctx.strokeStyle = node.status === 'online' ? '#22c55e' : node.status === 'degraded' ? '#f59e0b' : '#ef4444'
      ctx.lineWidth = isSelected ? 3 : 2
      ctx.stroke()

      // Node icon (simplified)
      ctx.fillStyle = node.status === 'online' ? '#16a34a' : node.status === 'degraded' ? '#d97706' : '#dc2626'
      ctx.font = 'bold 12px system-ui'
      ctx.textAlign = 'center'
      ctx.fillText(node.type === 'router' ? 'R' : node.type === 'switch' ? 'S' : 'FW', node.x, node.y + 4)

      // Node label
      ctx.fillStyle = '#1f2937'
      ctx.font = '11px system-ui'
      ctx.textAlign = 'center'
      ctx.fillText(node.id, node.x, node.y + 45)
      ctx.fillStyle = '#6b7280'
      ctx.font = '10px system-ui'
      ctx.fillText(node.ip, node.x, node.y + 57)
    })

    ctx.restore()
  }, [nodes, links, scale, offset, selectedNode])

  useEffect(() => {
    draw()
  }, [draw])

  const handleClick = (e: React.MouseEvent<HTMLCanvasElement>) => {
    const canvas = canvasRef.current
    if (!canvas) return
    const rect = canvas.getBoundingClientRect()
    const x = (e.clientX - rect.left - offset.x) / scale
    const y = (e.clientY - rect.top - offset.y) / scale

    const clickedNode = nodes.find((n) => {
      const dist = Math.sqrt((n.x - x) ** 2 + (n.y - y) ** 2)
      return dist < 30
    })
    setSelectedNode(clickedNode || null)
  }

  return (
    <div className="relative w-full h-[500px] border rounded-lg bg-muted/20">
      <div className="absolute top-2 right-2 z-10 flex gap-2">
        <Button variant="outline" size="icon" onClick={() => setScale((s) => Math.min(s + 0.2, 2))}>
          <ZoomIn className="h-4 w-4" />
        </Button>
        <Button variant="outline" size="icon" onClick={() => setScale((s) => Math.max(s - 0.2, 0.5))}>
          <ZoomOut className="h-4 w-4" />
        </Button>
        <Button variant="outline" size="icon" onClick={() => { setScale(1); setOffset({ x: 50, y: 50 }); }}>
          <Maximize2 className="h-4 w-4" />
        </Button>
      </div>

      <canvas
        ref={canvasRef}
        className="w-full h-full cursor-pointer"
        onClick={handleClick}
      />

      {selectedNode && (
        <div className="absolute bottom-4 left-4 bg-background border rounded-lg p-4 shadow-lg min-w-[200px]">
          <div className="flex items-center gap-2 mb-2">
            <NodeIcon type={selectedNode.type} status={selectedNode.status} />
            <div>
              <h4 className="font-semibold">{selectedNode.id}</h4>
              <p className="text-sm text-muted-foreground">{selectedNode.vendor} {selectedNode.model}</p>
            </div>
          </div>
          <div className="space-y-1 text-sm">
            <div className="flex justify-between">
              <span className="text-muted-foreground">IP:</span>
              <span className="font-mono">{selectedNode.ip}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-muted-foreground">Status:</span>
              <Badge variant={selectedNode.status === 'online' ? 'success' : selectedNode.status === 'degraded' ? 'warning' : 'destructive'}>
                {selectedNode.status}
              </Badge>
            </div>
            <div className="flex justify-between">
              <span className="text-muted-foreground">Type:</span>
              <span className="capitalize">{selectedNode.type}</span>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

export function TopologyPage() {
  const { t } = useTranslation()

  const { data: topology, isLoading, refetch } = useQuery({
    queryKey: ['topology'],
    queryFn: () => topologyApi.get(),
  })

  const nodes = topology?.nodes || []
  const links = topology?.links || []
  const vlans = topology?.vlans || []

  const onlineNodes = nodes.filter((n) => n.status === 'online').length
  const degradedNodes = nodes.filter((n) => n.status === 'degraded').length
  const offlineNodes = nodes.filter((n) => n.status === 'offline').length
  const upLinks = links.filter((l) => l.status === 'up').length
  const degradedLinks = links.filter((l) => l.status === 'degraded').length

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold">Топология сети</h1>
          <p className="text-muted-foreground">Визуализация сетевой инфраструктуры</p>
        </div>
        <Button onClick={() => refetch()} disabled={isLoading}>
          <RefreshCw className={`mr-2 h-4 w-4 ${isLoading ? 'animate-spin' : ''}`} />
          Обновить
        </Button>
      </div>

      {/* Stats */}
      <div className="grid gap-4 md:grid-cols-4">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Устройства</CardTitle>
            <Server className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{nodes.length}</div>
            <p className="text-xs text-muted-foreground">
              <span className="text-green-500">{onlineNodes} online</span>
              {degradedNodes > 0 && <span className="text-yellow-500 ml-2">{degradedNodes} degraded</span>}
              {offlineNodes > 0 && <span className="text-red-500 ml-2">{offlineNodes} offline</span>}
            </p>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Соединения</CardTitle>
            <Network className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{links.length}</div>
            <p className="text-xs text-muted-foreground">
              <span className="text-green-500">{upLinks} active</span>
              {degradedLinks > 0 && <span className="text-yellow-500 ml-2">{degradedLinks} degraded</span>}
            </p>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">VLAN</CardTitle>
            <Network className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{vlans.length}</div>
            <p className="text-xs text-muted-foreground">Настроенные сегменты</p>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Проблемы</CardTitle>
            <AlertTriangle className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-yellow-500">{degradedNodes + degradedLinks}</div>
            <p className="text-xs text-muted-foreground">Требуют внимания</p>
          </CardContent>
        </Card>
      </div>

      <Tabs defaultValue="diagram">
        <TabsList>
          <TabsTrigger value="diagram">Диаграмма</TabsTrigger>
          <TabsTrigger value="nodes">Устройства</TabsTrigger>
          <TabsTrigger value="links">Соединения</TabsTrigger>
          <TabsTrigger value="vlans">VLAN</TabsTrigger>
        </TabsList>

        <TabsContent value="diagram">
          <Card>
            <CardHeader>
              <CardTitle>Сетевая топология</CardTitle>
              <CardDescription>Интерактивная карта сети. Кликните на устройство для просмотра деталей.</CardDescription>
            </CardHeader>
            <CardContent>
              <TopologyCanvas nodes={nodes} links={links} />
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="nodes">
          <Card>
            <CardHeader>
              <CardTitle>Устройства</CardTitle>
              <CardDescription>Все устройства в топологии</CardDescription>
            </CardHeader>
            <CardContent>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Имя</TableHead>
                    <TableHead>Тип</TableHead>
                    <TableHead>Вендор / Модель</TableHead>
                    <TableHead>IP адрес</TableHead>
                    <TableHead>Статус</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {nodes.map((node) => (
                    <TableRow key={node.id}>
                      <TableCell className="font-medium">{node.id}</TableCell>
                      <TableCell className="capitalize">{node.type}</TableCell>
                      <TableCell>{node.vendor} {node.model}</TableCell>
                      <TableCell className="font-mono">{node.ip}</TableCell>
                      <TableCell>
                        <Badge variant={node.status === 'online' ? 'success' : node.status === 'degraded' ? 'warning' : 'destructive'}>
                          {node.status === 'online' ? <Wifi className="mr-1 h-3 w-3" /> : <WifiOff className="mr-1 h-3 w-3" />}
                          {node.status}
                        </Badge>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="links">
          <Card>
            <CardHeader>
              <CardTitle>Соединения</CardTitle>
              <CardDescription>Все сетевые соединения</CardDescription>
            </CardHeader>
            <CardContent>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Источник</TableHead>
                    <TableHead>Назначение</TableHead>
                    <TableHead>Тип</TableHead>
                    <TableHead>Скорость</TableHead>
                    <TableHead>Статус</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {links.map((link, i) => (
                    <TableRow key={i}>
                      <TableCell className="font-medium">{link.source}</TableCell>
                      <TableCell className="font-medium">{link.target}</TableCell>
                      <TableCell className="capitalize">{link.type}</TableCell>
                      <TableCell>{link.bandwidth}</TableCell>
                      <TableCell>
                        <Badge variant={link.status === 'up' ? 'success' : link.status === 'degraded' ? 'warning' : 'destructive'}>
                          {link.status}
                        </Badge>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="vlans">
          <Card>
            <CardHeader>
              <CardTitle>VLAN</CardTitle>
              <CardDescription>Настроенные виртуальные сети</CardDescription>
            </CardHeader>
            <CardContent>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>ID</TableHead>
                    <TableHead>Имя</TableHead>
                    <TableHead>Подсеть</TableHead>
                    <TableHead>Шлюз</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {vlans.map((vlan) => (
                    <TableRow key={vlan.id}>
                      <TableCell className="font-medium">{vlan.id}</TableCell>
                      <TableCell>{vlan.name}</TableCell>
                      <TableCell className="font-mono">{vlan.subnet}</TableCell>
                      <TableCell className="font-mono">{vlan.gateway}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  )
}
