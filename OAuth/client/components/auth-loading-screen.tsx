"use client"

import { Loader2, Shield } from "lucide-react"

interface AuthLoadingScreenProps {
  message?: string
}

export function AuthLoadingScreen({ message = "Authenticating..." }: AuthLoadingScreenProps) {
  return (
    <div className="min-h-screen bg-background flex items-center justify-center">
      <div className="text-center space-y-8 animate-slide-in">
        {/* Logo/Icon */}
        <div className="flex justify-center">
          <div className="relative">
            <Shield className="h-16 w-16 text-primary animate-pulse-glow" />
            <div className="absolute inset-0 flex items-center justify-center">
              <Loader2 className="h-8 w-8 text-primary-foreground animate-spin" />
            </div>
          </div>
        </div>

        {/* Loading Message */}
        <div className="space-y-4">
          <h2 className="text-2xl font-semibold text-foreground">{message}</h2>
          <p className="text-muted-foreground max-w-md">Please wait while we securely process your request...</p>
        </div>

        {/* Progress Indicator */}
        <div className="w-64 mx-auto">
          <div className="h-1 bg-secondary/20 rounded-full overflow-hidden">
            <div className="h-full bg-primary rounded-full animate-pulse w-full"></div>
          </div>
        </div>

        {/* Floating Elements */}
        <div className="absolute inset-0 overflow-hidden pointer-events-none">
          <div className="absolute top-1/4 left-1/4 w-2 h-2 bg-primary/30 rounded-full animate-float"></div>
          <div
            className="absolute top-3/4 right-1/4 w-3 h-3 bg-accent/20 rounded-full animate-float"
            style={{ animationDelay: "1s" }}
          ></div>
          <div
            className="absolute top-1/2 left-3/4 w-1 h-1 bg-primary/40 rounded-full animate-float"
            style={{ animationDelay: "2s" }}
          ></div>
        </div>
      </div>
    </div>
  )
}
