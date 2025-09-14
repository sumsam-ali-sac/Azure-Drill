import type React from "react"
export interface User {
  id: string
  email: string
  name: string
  avatar?: string
  provider: "email" | "google" | "azure"
  role: "admin" | "user" | "viewer"
  permissions: string[]
  createdAt: Date
  lastLoginAt?: Date
}

export interface AuthState {
  user: User | null
  isLoading: boolean
  isAuthenticated: boolean
}

export interface LoginCredentials {
  email: string
  password: string
}

export interface SignupCredentials {
  name: string
  email: string
  password: string
}

export interface SocialAuthProvider {
  id: "google" | "azure"
  name: string
  icon: React.ComponentType<{ className?: string }>
  color: string
  authUrl: string
}

export interface AuthResponse {
  user: User
  message?: string
}

export interface ApiError {
  detail: string
  code?: string
}
