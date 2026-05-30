/**
 * Sign-out button — client component so it can use onClick.
 * Author: Matthew Faber
 */
"use client";

export function SignOutButton() {
  return (
    <button
      className="hover:text-slate-100"
      onClick={() => {
        if (typeof window !== "undefined") {
          localStorage.removeItem("loginsight_token");
          window.location.href = "/login";
        }
      }}
    >
      Sign out
    </button>
  );
}
