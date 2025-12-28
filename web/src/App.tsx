import { Routes, Route, Navigate } from 'react-router-dom'
import { useAuthStore } from '@/stores/auth'
import { MainLayout } from '@/components/layout/MainLayout'
import { LoginPage } from '@/pages/LoginPage'
import { DashboardPage } from '@/pages/DashboardPage'
import { DevicesPage } from '@/pages/DevicesPage'
import { IdentitiesPage } from '@/pages/IdentitiesPage'
import { PoliciesPage } from '@/pages/PoliciesPage'
import { CapabilitiesPage } from '@/pages/CapabilitiesPage'
import { ConfigsPage } from '@/pages/ConfigsPage'
import { AuditPage } from '@/pages/AuditPage'
import { MonitoringPage } from '@/pages/MonitoringPage'
import { TopologyPage } from '@/pages/TopologyPage'
import { DeviceDetailPage } from '@/pages/DeviceDetailPage'
import { IdentityDetailPage } from '@/pages/IdentityDetailPage'
import { PolicyDetailPage } from '@/pages/PolicyDetailPage'
import { ProfilePage } from '@/pages/ProfilePage'
import { SettingsPage } from '@/pages/SettingsPage'

function ProtectedRoute({ children }: { children: React.ReactNode }) {
  const { isAuthenticated } = useAuthStore()

  if (!isAuthenticated) {
    return <Navigate to="/login" replace />
  }

  return <>{children}</>
}

function App() {
  return (
    <Routes>
      <Route path="/login" element={<LoginPage />} />
      <Route
        path="/*"
        element={
          <ProtectedRoute>
            <MainLayout>
              <Routes>
                <Route path="/" element={<DashboardPage />} />
                <Route path="/devices" element={<DevicesPage />} />
                <Route path="/devices/:id" element={<DeviceDetailPage />} />
                <Route path="/identities" element={<IdentitiesPage />} />
                <Route path="/identities/:id" element={<IdentityDetailPage />} />
                <Route path="/policies" element={<PoliciesPage />} />
                <Route path="/policies/:id" element={<PolicyDetailPage />} />
                <Route path="/capabilities" element={<CapabilitiesPage />} />
                <Route path="/configs" element={<ConfigsPage />} />
                <Route path="/audit" element={<AuditPage />} />
                <Route path="/monitoring" element={<MonitoringPage />} />
                <Route path="/topology" element={<TopologyPage />} />
                <Route path="/profile" element={<ProfilePage />} />
                <Route path="/settings" element={<SettingsPage />} />
              </Routes>
            </MainLayout>
          </ProtectedRoute>
        }
      />
    </Routes>
  )
}

export default App
