"use client";

import type React from "react";

import { useState, useEffect } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
	Card,
	CardContent,
	CardDescription,
	CardHeader,
	CardTitle,
} from "@/components/ui/card";
import { Separator } from "@/components/ui/separator";
import { Eye, EyeOff, Mail, Lock, Loader2, Shield } from "lucide-react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { AuthLoadingScreen } from "@/components/auth/auth-loading-screen";
import { SocialAuthButtons } from "@/components/auth/social-auth-buttons";
import { useAuth } from "@/hooks/use-auth";

export default function LoginPage() {
	const [showPassword, setShowPassword] = useState(false);
	const [isLoading, setIsLoading] = useState(false);
	const [error, setError] = useState("");
	const [formData, setFormData] = useState({
		email: "",
		password: "",
	});

	const { login, isAuthenticated } = useAuth();
	const router = useRouter();

	// Redirect if already authenticated
	useEffect(() => {
		if (isAuthenticated) {
			router.push("/");
		}
	}, [isAuthenticated, router]);

	const handleSubmit = async (e: React.FormEvent) => {
		e.preventDefault();
		setError("");
		setIsLoading(true);

		try {
			const result = await login(formData);

			if (result.success) {
				setError(result.error || "Login failed");
			} else {
				router.push("/");
			}
		} catch (error) {
			setError("An unexpected error occurred");
		} finally {
			setIsLoading(false);
		}
	};

	if (isLoading) {
		return <AuthLoadingScreen message="Signing you in..." />;
	}

	return (
		<div className="min-h-screen bg-gradient-to-br from-background via-background to-background/95 flex items-center justify-center p-4 relative overflow-hidden">
			<div className="absolute inset-0 bg-[radial-gradient(circle_at_50%_50%,rgba(99,102,241,0.1),transparent_50%)]" />
			<div className="absolute top-0 left-0 w-full h-full bg-[linear-gradient(45deg,transparent_25%,rgba(99,102,241,0.02)_50%,transparent_75%)]" />

			<div className="w-full max-w-md space-y-8 animate-fade-in-up relative z-10">
				<div className="text-center space-y-4">
					<div className="mx-auto w-16 h-16 bg-gradient-to-br from-primary to-accent rounded-2xl flex items-center justify-center animate-breathe">
						<Shield className="w-8 h-8 text-white" />
					</div>
					<div className="space-y-2">
						<h1 className="text-4xl font-bold tracking-tight text-foreground">
							Welcome Back
						</h1>
						<p className="text-muted-foreground text-lg">
							Sign in to your enterprise account
						</p>
					</div>
				</div>

				<Card className="border-border/50 bg-card/80 backdrop-blur-xl shadow-2xl shadow-primary/5 animate-scale-in animate-delay-200">
					<CardHeader className="space-y-2 pb-6">
						<CardTitle className="text-2xl text-center font-semibold">
							Sign In
						</CardTitle>
						<CardDescription className="text-center text-base">
							Enter your credentials to access your account
						</CardDescription>
					</CardHeader>
					<CardContent className="space-y-6">
						{/* Error Message */}
						{error && (
							<div className="p-4 text-sm text-destructive-foreground bg-destructive/10 border border-destructive/20 rounded-lg animate-slide-in">
								{error}
							</div>
						)}

						{/* Social Auth */}
						<div className="animate-slide-in-left animate-delay-300">
							<SocialAuthButtons />
						</div>

						<div className="relative animate-slide-in animate-delay-500">
							<div className="absolute inset-0 flex items-center">
								<Separator className="w-full bg-border/60" />
							</div>
							<div className="relative flex justify-center text-xs uppercase">
								<span className="bg-card px-4 text-muted-foreground font-medium">
									Or continue with email
								</span>
							</div>
						</div>

						<form
							onSubmit={handleSubmit}
							className="space-y-5 animate-slide-in-right animate-delay-500">
							<div className="space-y-2">
								<Label
									htmlFor="email"
									className="text-sm font-medium">
									Email Address
								</Label>
								<div className="relative group">
									<Mail className="absolute left-3 top-3 h-4 w-4 text-muted-foreground group-focus-within:text-primary transition-colors" />
									<Input
										id="email"
										type="email"
										placeholder="Enter your email"
										className="pl-10 h-12 bg-input/50 border-border/60 focus:border-primary/50 focus:bg-input transition-all"
										value={formData.email}
										onChange={(e) =>
											setFormData((prev) => ({
												...prev,
												email: e.target.value,
											}))
										}
										required
									/>
								</div>
							</div>

							<div className="space-y-2">
								<Label
									htmlFor="password"
									className="text-sm font-medium">
									Password
								</Label>
								<div className="relative group">
									<Lock className="absolute left-3 top-3 h-4 w-4 text-muted-foreground group-focus-within:text-primary transition-colors" />
									<Input
										id="password"
										type={
											showPassword ? "text" : "password"
										}
										placeholder="Enter your password"
										className="pl-10 pr-12 h-12 bg-input/50 border-border/60 focus:border-primary/50 focus:bg-input transition-all"
										value={formData.password}
										onChange={(e) =>
											setFormData((prev) => ({
												...prev,
												password: e.target.value,
											}))
										}
										required
									/>
									<Button
										type="button"
										variant="ghost"
										size="sm"
										className="absolute right-1 top-1 h-10 w-10 hover:bg-transparent"
										onClick={() =>
											setShowPassword(!showPassword)
										}>
										{showPassword ? (
											<EyeOff className="h-4 w-4 text-muted-foreground" />
										) : (
											<Eye className="h-4 w-4 text-muted-foreground" />
										)}
									</Button>
								</div>
							</div>

							<div className="flex items-center justify-between">
								<Link
									href="/auth/forgot-password"
									className="text-sm text-primary hover:text-primary/80 transition-colors font-medium">
									Forgot password?
								</Link>
							</div>

							<Button
								type="submit"
								className="w-full h-12 bg-gradient-to-r from-primary to-accent hover:from-primary/90 hover:to-accent/90 text-white font-medium shadow-lg shadow-primary/25 transition-all duration-200"
								disabled={isLoading}>
								{isLoading ? (
									<>
										<Loader2 className="mr-2 h-4 w-4 animate-spin" />
										Signing in...
									</>
								) : (
									"Sign In"
								)}
							</Button>
						</form>

						<div className="text-center text-sm animate-fade-in-up animate-delay-500">
							<span className="text-muted-foreground">
								Don't have an account?{" "}
							</span>
							<Link
								href="/auth/signup"
								className="text-primary hover:text-primary/80 transition-colors font-medium">
								Sign up
							</Link>
						</div>
					</CardContent>
				</Card>
			</div>
		</div>
	);
}
