// 空状态组件。
//
// 空状态要说清两件事：为什么空，以及接下来做什么。
// 只说"暂无数据"是信息量为零的 UI。
export interface EmptyStateProps {
  title: string;
  description: React.ReactNode;
}

export function EmptyState(props: EmptyStateProps) {
  return (
    <div className="empty-state">
      <h2>{props.title}</h2>
      <div className="empty-state-body">{props.description}</div>
    </div>
  );
}
