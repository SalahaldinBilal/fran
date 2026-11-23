/* @refresh reload */
import { render } from "@solidjs/web";
import "@fontsource-variable/inter/index.css";
import "./styles/global.scss";
import App from "./App";

render(() => <App />, document.getElementById("root") as HTMLElement);
