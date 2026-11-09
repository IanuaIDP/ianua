/** Who a run acted for or who owns an account, as the dashboard can say it. */
export type ActorWord = 'you' | 'person' | 'system';

export function getActorWord(actor: string, caller: string | null): ActorWord {
  if (actor === caller) {
    return 'you';
  }

  return actor === 'system' || actor === 'anonymous' ? 'system' : 'person';
}
