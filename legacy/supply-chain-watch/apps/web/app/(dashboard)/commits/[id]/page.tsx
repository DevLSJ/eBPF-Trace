import { CommitDetail } from '@/components/commit-detail';

export default async function CommitDetailPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  return <CommitDetail id={id} />;
}
