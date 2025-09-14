"use client"

import { useState, useEffect } from "react"
import { Button } from "@/components/ui/button"
import { Card } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Shield, ShieldAlert, Sparkles, ArrowRight, RefreshCw, Mail, Settings, User, LogOut } from "lucide-react"
import { useAuth } from "@/hooks/use-auth"
import { useRouter } from "next/navigation"

interface WelcomeScreenProps {
  userAccess: "loading" | "granted" | "denied"
  userName: string
  onRetry: () => void
}

export function WelcomeScreen({ userAccess, userName, onRetry }: WelcomeScreenProps) {
  const [mounted, setMounted] = useState(false)

  useEffect(() => {
    setMounted(true)
  }, [])

  if (!mounted) return null

  return (
    <div className="min-h-screen bg-gradient-to-br from-background via-background to-card relative overflow-hidden">
      {/* Animated background elements */}
      <div className="absolute inset-0 overflow-hidden">
        <div className="absolute -top-40 -right-40 w-80 h-80 bg-primary/10 rounded-full blur-3xl animate-float" />
        <div
          className="absolute -bottom-40 -left-40 w-80 h-80 bg-accent/10 rounded-full blur-3xl animate-float"
          style={{ animationDelay: "1s" }}
        />
        <div className="absolute top-1/2 left-1/2 transform -translate-x-1/2 -translate-y-1/2 w-96 h-96 bg-primary/5 rounded-full blur-3xl animate-pulse" />
      </div>

      <div className="relative z-10 flex items-center justify-center min-h-screen p-6">
        <div className="w-full max-w-2xl mx-auto">
          {userAccess === "loading" && <LoadingState />}

          {userAccess === "granted" && <WelcomeState userName={userName} />}

          {userAccess === "denied" && <AccessDeniedState onRetry={onRetry} />}
        </div>
      </div>
    </div>
  )
}

function LoadingState() {
  return (
    <div className="text-center animate-slide-in">
      <div className="mb-8">
        <div className="w-20 h-20 mx-auto mb-6 bg-primary/20 rounded-full flex items-center justify-center animate-pulse-glow">
          <Shield className="w-10 h-10 text-primary animate-pulse" />
        </div>
        <h1 className="text-4xl font-black text-foreground mb-4 font-mono tracking-tight">Authenticating...</h1>
        <p className="text-muted-foreground text-lg">Verifying your access permissions</p>
      </div>

      <div className="flex justify-center">
        <div className="flex space-x-2">
          <div className="w-3 h-3 bg-primary rounded-full animate-bounce" />
          <div className="w-3 h-3 bg-primary rounded-full animate-bounce" style={{ animationDelay: "0.1s" }} />
          <div className="w-3 h-3 bg-primary rounded-full animate-bounce" style={{ animationDelay: "0.2s" }} />
        </div>
      </div>
    </div>
  )
}

function WelcomeState({ userName }: { userName: string }) {
  const { logout, user } = useAuth()
  const router = useRouter()

  const handleLogout = async () => {
    const result = await logout()
    if (result.success) {
      router.push("/auth/login")
    }
  }

  return (
    <div className="text-center animate-slide-in">
      <div className="absolute top-6 right-6">
        <div className="flex items-center gap-4">
          <div className="text-right">
            <p className="text-sm font-medium text-foreground">{userName}</p>
            <p className="text-xs text-muted-foreground capitalize">{user?.role || "User"}</p>
          </div>
          <Button
            variant="outline"
            size="sm"
            onClick={handleLogout}
            className="hover:bg-destructive/10 hover:text-destructive hover:border-destructive/20 bg-transparent"
          >
            <LogOut className="w-4 h-4 mr-2" />
            Logout
          </Button>
        </div>
      </div>

      <div className="mb-8">
        <div className="w-24 h-24 mx-auto mb-6 bg-primary/20 rounded-full flex items-center justify-center animate-pulse-glow">
          <Sparkles className="w-12 h-12 text-primary" />
        </div>

        <Badge
          variant="secondary"
          className="mb-4 px-4 py-2 text-sm font-medium bg-primary/10 text-primary border-primary/20"
        >
          Access Granted
        </Badge>

        <h1 className="text-5xl font-black text-foreground mb-4 font-mono tracking-tight text-balance">
          Welcome Back,
          <span className="block text-primary mt-2">{userName}!</span>
        </h1>

        <p className="text-muted-foreground text-xl mb-8 text-pretty">
          {"Ready to dive into your enterprise dashboard? Let's make today productive."}
        </p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-8 animate-slide-in-delay">
        <Card className="p-6 bg-card/50 backdrop-blur-sm border-border/50 hover:bg-card/70 transition-all duration-300 hover:scale-105 cursor-pointer">
          <User className="w-8 h-8 text-primary mb-3" />
          <h3 className="font-semibold text-card-foreground mb-2">Profile</h3>
          <p className="text-sm text-muted-foreground">Manage your account</p>
        </Card>

        <Card className="p-6 bg-card/50 backdrop-blur-sm border-border/50 hover:bg-card/70 transition-all duration-300 hover:scale-105 cursor-pointer">
          <Settings className="w-8 h-8 text-primary mb-3" />
          <h3 className="font-semibold text-card-foreground mb-2">Settings</h3>
          <p className="text-sm text-muted-foreground">Configure preferences</p>
        </Card>

        <Card className="p-6 bg-card/50 backdrop-blur-sm border-border/50 hover:bg-card/70 transition-all duration-300 hover:scale-105 cursor-pointer">
          <Mail className="w-8 h-8 text-primary mb-3" />
          <h3 className="font-semibold text-card-foreground mb-2">Messages</h3>
          <p className="text-sm text-muted-foreground">Check notifications</p>
        </Card>
      </div>

      <Button
        size="lg"
        className="bg-primary hover:bg-primary/90 text-primary-foreground px-8 py-4 text-lg font-semibold rounded-xl transition-all duration-300 hover:scale-105 hover:shadow-lg hover:shadow-primary/25 group"
      >
        Enter Dashboard
        <ArrowRight className="ml-2 w-5 h-5 group-hover:translate-x-1 transition-transform" />
      </Button>
    </div>
  )
}

function AccessDeniedState({ onRetry }: { onRetry: () => void }) {
  const { logout } = useAuth()
  const router = useRouter()

  const handleLogout = async () => {
    const result = await logout()
    if (result.success) {
      router.push("/auth/login")
    }
  }

  return (
    <div className="text-center animate-slide-in">
      <div className="mb-8">
        <div className="w-24 h-24 mx-auto mb-6 bg-destructive/20 rounded-full flex items-center justify-center animate-pulse">
          <ShieldAlert className="w-12 h-12 text-destructive" />
        </div>

        <Badge variant="destructive" className="mb-4 px-4 py-2 text-sm font-medium">
          Access Denied
        </Badge>

        <h1 className="text-5xl font-black text-foreground mb-4 font-mono tracking-tight text-balance">
          Access
          <span className="block text-destructive mt-2">Restricted</span>
        </h1>

        <p className="text-muted-foreground text-xl mb-8 text-pretty">
          {"You don't have permission to access this application. Please contact your administrator for assistance."}
        </p>
      </div>

      <Card className="p-8 bg-destructive/5 backdrop-blur-sm border-destructive/20 mb-8 animate-slide-in-delay">
        <div className="text-center">
          <h3 className="text-lg font-semibold text-card-foreground mb-2">Need Help?</h3>
          <p className="text-muted-foreground mb-4">Contact your system administrator or IT support team</p>
          <div className="flex flex-col sm:flex-row gap-3 justify-center">
            <Button
              variant="outline"
              className="border-border hover:bg-card/50 bg-transparent"
              onClick={() => (window.location.href = "mailto:admin@company.com")}
            >
              <Mail className="w-4 h-4 mr-2" />
              Email Admin
            </Button>
            <Button variant="outline" className="border-border hover:bg-card/50 bg-transparent" onClick={onRetry}>
              <RefreshCw className="w-4 h-4 mr-2" />
              Try Again
            </Button>
            <Button
              variant="outline"
              className="border-destructive/20 hover:bg-destructive/10 hover:text-destructive bg-transparent"
              onClick={handleLogout}
            >
              <LogOut className="w-4 h-4 mr-2" />
              Logout
            </Button>
          </div>
        </div>
      </Card>
    </div>
  )
}
