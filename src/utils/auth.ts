import { createStore } from "solid-js/store";

export const [auth, setAuth] = createStore<Auth>({
  isAuthed: false,
  username: undefined,
  login: (username: string, password: string) => {
    const key = "slem.auth.username";
    const token = "slem.auth.token";
    if (username === "demo" && password === "demo123") {
      localStorage.setItem(key, username);
      localStorage.setItem(token, "token");
      setAuth({
        isAuthed: true,
        username,
      });
    } else {
      localStorage.removeItem(key);
      localStorage.removeItem(token);
      setAuth({
        isAuthed: false,
        username: undefined,
      });
    }
  },
  logout: () => {
    localStorage.removeItem("slem.auth.username");
    localStorage.removeItem("slem.auth.token");
    setAuth({
      isAuthed: false,
      username: undefined,
    });
  },
});

export type Auth = {
  login: (username: string, password: string) => void;
  logout: () => void;
  isAuthed: boolean;
  username?: string;
};
