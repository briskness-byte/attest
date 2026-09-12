import { useEffect, useState } from 'react';
import {
  addOpenPromptChangeListener,
  readOpenPrompts,
  removeOpenPromptChangeListener,
  updateOpenPrompts
} from './storage';
import { OpenPromptItem } from './types';

const managerFunctions = {
  add: async (item: OpenPromptItem) => {
    const openPrompts = (await readOpenPrompts()) ?? [];
    openPrompts.push(item);
    return await updateOpenPrompts(openPrompts);
  },
  get: async () => {
    return await readOpenPrompts();
  },
  remove: async (id: string) => {
    const openPrompts = (await readOpenPrompts()) ?? [];
    return await updateOpenPrompts(openPrompts.filter(item => item.id !== id));
  },
  clear: async () => {
    return await updateOpenPrompts([]);
  },
  addChangeListener: (callback: (newOpenPrompts: OpenPromptItem[]) => void) => {
    return addOpenPromptChangeListener(callback);
  },
  removeChangeListener: (listener: ReturnType<typeof addOpenPromptChangeListener>) => {
    return removeOpenPromptChangeListener(listener);
  }
};

export function useOpenPrompts() {
  const [openPrompts, setOpenPrompts] = useState<OpenPromptItem[]>([]);

  useEffect(() => {
    // initialize with existing open prompts
    managerFunctions.get().then((existingOpenPrompts: OpenPromptItem[]) => {
      setOpenPrompts(existingOpenPrompts);
    });

    const listener = (newOpenPrompts: OpenPromptItem[]) => {
      setOpenPrompts(newOpenPrompts);
    };
    // Keep what storage actually registered. Removing the callback handed to it removed nothing:
    // storage listens with a wrapper of its own, and that is a different function.
    const registered = managerFunctions.addChangeListener(listener);
    return () => {
      managerFunctions.removeChangeListener(registered);
    };
  }, []);

  return openPrompts;
}

export default managerFunctions;
