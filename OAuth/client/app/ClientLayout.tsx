"use client";

import type React from "react";
import { Inter, JetBrains_Mono } from "next/font/google";
import { Suspense } from "react";

const inter = Inter({
	subsets: ["latin"],
	variable: "--font-inter",
	weight: ["300", "400", "500", "600", "700", "800", "900"],
});

const jetbrainsMono = JetBrains_Mono({
	subsets: ["latin"],
	variable: "--font-jetbrains-mono",
	weight: ["300", "400", "500", "600", "700", "800"],
});

export default function ClientLayout({
	children,
}: Readonly<{
	children: React.ReactNode;
}>) {
	return (
		<div className={`${inter.variable} ${jetbrainsMono.variable}`}>
			<Suspense fallback={<div>Loading...</div>}>{children}</Suspense>
		</div>
	);
}
