import { createFileRoute } from "@tanstack/solid-router";
import Counter from "~/components/Counter";

export const Route = createFileRoute("/")({
  component: RouteComponent,
});

function RouteComponent() {
  return (
    <div class="">
      <h1>Hello world!</h1>
      <Counter />
      <button class="bg-gradient-to-br from-blue-500 to-blue-700 text-white font-bold py-2 px-4 rounded hover:from-blue-700 hover:to-blue-900">
        发光按钮
      </button>
      <button class="ml-5 py-2 px-6 text-bold text-amber-500 border-none rounded-2xl hover:outline hover:outline-blue-500 hover:shadow-blue-200 hover:shadow-lg">
        按钮
      </button>
      <p>
        Visit{" "}
        <a href="https://start.solidjs.com" target="_blank">
          start.solidjs.com
        </a>{" "}
        to learn how to build SolidStart apps.
      </p>
    </div>
  );
}
