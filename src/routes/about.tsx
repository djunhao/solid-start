import { createFileRoute } from "@tanstack/solid-router";
import { createSignal } from "solid-js";

export const Route = createFileRoute("/about")({
  component: RouteComponent,
});

function RouteComponent() {
  const [test, setTest] = createSignal("");
  setTest("John Doe");
  return (
    <div class="">
      <h1>About {test()}</h1>
    </div>
  );
}
