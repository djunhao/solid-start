import { createFileRoute } from "@tanstack/solid-router";
import Counter from "~/components/Counter";
import { For } from "solid-js";

export const Route = createFileRoute("/")({
  loader: async () => {
    const response = await fetch("https://jsonplaceholder.typicode.com/posts");
    const data = await response.json();
    return data;
  },
  component: RouteComponent,
});

function RouteComponent() {
  const message = Route.useLoaderData();
  return (
    <div>
      <h1>Hello World</h1>
      <For each={message()}>
        {(item) => (
          <div id={item.id} class="align-left">
            <h2>{item.title}</h2>
            <p>{item.body}</p>
          </div>
        )}
      </For>

      <Counter />
      <button class="bg-linear-to-br from-blue-500 to-blue-700 text-white font-bold py-2 px-4 rounded hover:from-blue-700 hover:to-blue-900">
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
