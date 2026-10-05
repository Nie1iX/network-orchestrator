import { Component, ReactNode } from "react";
import { useT } from "../i18n";

interface Props {
  children: ReactNode;
  label: string;
}

interface State {
  error: string | null;
}

/** One failing panel must not unmount the whole app — there is no global
 *  error boundary, so each route tab renders inside this guard and shows
 *  the error inline instead of a blank window. */
class Boundary extends Component<Props, State> {
  state: State = { error: null };

  static getDerivedStateFromError(err: unknown): State {
    return { error: String(err) };
  }

  componentDidCatch(err: unknown) {
    console.error("panel render failed:", err);
  }

  render() {
    if (this.state.error !== null) {
      return (
        <p className="error">
          {this.props.label}: {this.state.error}
        </p>
      );
    }
    return this.props.children;
  }
}

export default function PanelBoundary({ children }: { children: ReactNode }) {
  const t = useT();
  return <Boundary label={t("common.panelError")}>{children}</Boundary>;
}
