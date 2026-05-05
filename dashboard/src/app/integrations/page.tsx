import { redirect } from "next/navigation";

export default function IntegrationsRedirect() {
  redirect("/settings?tab=services");
}
