import { Injectable } from "@angular/core";
import { Audit } from "./models";

@Injectable({ providedIn: "root" })
export class AuditService {
  private async request<T>(path: string, options?: RequestInit): Promise<T> {
    let response: Response;
    try {
      response = await fetch(path, {
        ...options,
        signal: AbortSignal.timeout(45000),
      });
    } catch {
      throw new Error(
        "Le serveur est injoignable ou le délai de réponse est dépassé.",
      );
    }
    let payload;
    try {
      payload = await response.json();
    } catch {
      throw new Error(
        "Réponse invalide du serveur. Vérifiez que le backend Python est lancé.",
      );
    }
    if (!response.ok) throw new Error(payload.error || "La requête a échoué.");
    return payload as T;
  }

  list(): Promise<Audit[]> {
    return this.request<Audit[]>("/api/audits");
  }

  run(target: string, includeCves: boolean): Promise<Audit> {
    return this.request<Audit>("/api/audits", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ target, authorized: true, includeCves }),
    });
  }
}
