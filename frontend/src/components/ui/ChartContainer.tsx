import type {
  ReactNode,
} from "react";


type ChartContainerProps = {
  title: string;
  description?: string;
  children: ReactNode;
};


export function ChartContainer({
  title,
  description,
  children,
}: ChartContainerProps) {
  return (
    <section className="chart-container">
      <header className="chart-container__header">
        <h2>
          {title}
        </h2>

        {description && (
          <p>
            {description}
          </p>
        )}
      </header>

      <div className="chart-container__body">
        {children}
      </div>
    </section>
  );
}