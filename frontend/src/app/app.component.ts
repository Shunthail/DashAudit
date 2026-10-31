import {
  HostListener,
  Component,
  computed,
  inject,
  signal,
} from "@angular/core";
import { CommonModule } from "@angular/common";
import { FormsModule } from "@angular/forms";
import { AuditService } from "./audit.service";
import { Audit, Severity } from "./models";

type View = "overview" | "assets" | "history" | "alerts";
@Component({
  selector: "app-root",
  standalone: true,
  imports: [CommonModule, FormsModule],
  templateUrl: "./app.component.html",
})
export class AppComponent {
  private readonly api = inject(AuditService);
  readonly audits = signal<Audit[]>([]);
  readonly connected = signal(false);
  readonly loading = signal(true);
  readonly busy = signal(false);
  readonly message = signal("");
  readonly view = signal<View>("overview");
  readonly query = signal("");
  readonly severity = signal("all");
  readonly days = signal(30);
  readonly selected = signal<Audit | null>(null);
  readonly showForm = signal(false);
  target = "";
  authorized = false;
  includeCves = true;
  readonly titles: Record<View, string> = {
    overview: "Suivi de sécurité",
    assets: "Surface surveillée",
    history: "Historique des audits",
    alerts: "Centre d’alertes",
  };
  readonly severityLabels: Record<Severity | "safe", string> = {
    safe: "Sain",
    critical: "Critique",
    high: "Élevée",
    medium: "Modérée",
    low: "Faible",
  };
  readonly periodAudits = computed(() =>
    this.audits().filter(
      (a) => Date.now() - new Date(a.date).getTime() <= this.days() * 86400000,
    ),
  );
  readonly assets = computed(() =>
    [
      ...new Map(
        [...this.periodAudits()].reverse().map((a) => [a.target, a]),
      ).values(),
    ].sort((a, b) => a.score - b.score),
  );
  readonly findings = computed(() =>
    this.assets().flatMap((a) => a.findings.map((f) => ({ ...f, audit: a }))),
  );
  readonly critical = computed(
    () => this.findings().filter((f) => f.severity === "critical").length,
  );
  readonly average = computed(() =>
    this.assets().length
      ? Math.round(
          this.assets().reduce((sum, a) => sum + a.score, 0) /
            this.assets().length,
        )
      : 0,
  );
  readonly rows = computed(() => {
    const source =
      this.view() === "history" ? this.periodAudits() : this.assets();
    return source.filter(
      (a) =>
        a.target.toLowerCase().includes(this.query().toLowerCase()) &&
        (this.severity() === "all" ||
          a.findings.some((f) => f.severity === this.severity())),
    );
  });
  readonly visibleFindings = computed(() =>
    this.findings().filter(
      (f) =>
        (this.severity() === "all" || f.severity === this.severity()) &&
        (f.title + f.audit.target)
          .toLowerCase()
          .includes(this.query().toLowerCase()),
    ),
  );
  readonly trend = computed(() => {
    const count = this.days() === 7 ? 7 : 14;
    return Array.from({ length: count }, (_, index) => {
      const date = new Date();
      date.setDate(date.getDate() - count + index + 1);
      const items = this.periodAudits().filter(
        (a) => new Date(a.date).toDateString() === date.toDateString(),
      );
      return {
        date,
        score: items.length
          ? Math.round(
              items.reduce((sum, a) => sum + a.score, 0) / items.length,
            )
          : null,
        count: items.length,
      };
    });
  });
  readonly chartPoints = computed(() =>
    this.trend()
      .map((d, i) =>
        d.score === null
          ? null
          : `${38 + (i * 660) / (this.trend().length - 1)},${165 - d.score * 1.35}`,
      )
      .filter(Boolean)
      .join(" "),
  );
  readonly chartArea = computed(() => {
    const points = this.chartPoints().split(" ").filter(Boolean);
    return points.length
      ? `${points[0].split(",")[0]},180 ${points.join(" ")} ${points[points.length - 1].split(",")[0]},180`
      : "";
  });
  @HostListener("document:keydown.escape")
  closeDialogs(): void {
    this.selected.set(null);
    if (!this.busy()) this.showForm.set(false);
  }

  constructor() {
    void this.load();
  }
  async load(): Promise<void> {
    this.loading.set(true);
    this.message.set("");
    try {
      const audits = await this.api.list();
      this.connected.set(true);
      this.audits.set(audits);
    } catch {
      this.connected.set(false);
      this.message.set(
        "Backend indisponible. Lancez le serveur Python pour charger les audits.",
      );
    } finally {
      this.loading.set(false);
    }
  }
  navigate(view: View): void {
    this.view.set(view);
    this.query.set("");
    this.severity.set("all");
  }
  host(target: string): string {
    try {
      return new URL(target.includes("://") ? target : "https://" + target)
        .host;
    } catch {
      return target;
    }
  }
  worst(audit: Audit): Severity | "safe" {
    return (
      (["critical", "high", "medium", "low"] as Severity[]).find((s) =>
        audit.findings.some((f) => f.severity === s),
      ) || "safe"
    );
  }
  count(severity: Severity): number {
    return this.findings().filter((f) => f.severity === severity).length;
  }
  share(severity: Severity): number {
    return this.findings().length
      ? (this.count(severity) / this.findings().length) * 100
      : 0;
  }
  async run(): Promise<void> {
    if (!this.target.trim() || !this.authorized || this.busy()) return;
    this.busy.set(true);
    this.message.set("");
    try {
      const audit = await this.api.run(this.target.trim(), this.includeCves);
      this.audits.update((items) => [audit, ...items]);
      this.connected.set(true);
      this.showForm.set(false);
      this.selected.set(audit);
      this.target = "";
      this.authorized = false;
    } catch (error) {
      this.message.set(
        error instanceof Error ? error.message : "L’audit a échoué.",
      );
    } finally {
      this.busy.set(false);
    }
  }
  exportData(): void {
    const data =
      this.view() === "alerts" ? this.visibleFindings() : this.rows();
    const url = URL.createObjectURL(
      new Blob([JSON.stringify(data, null, 2)], { type: "application/json" }),
    );
    const link = document.createElement("a");
    link.href = url;
    link.download = `dashaudit-${new Date().toISOString().slice(0, 10)}.json`;
    link.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }
}
