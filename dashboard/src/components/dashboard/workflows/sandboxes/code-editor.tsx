'use client';

import { useEffect, useRef } from 'react';
import { basicSetup } from 'codemirror';
import { javascript } from '@codemirror/lang-javascript';
import { python } from '@codemirror/lang-python';
import { HighlightStyle, syntaxHighlighting } from '@codemirror/language';
import { EditorState } from '@codemirror/state';
import { EditorView } from '@codemirror/view';
import { tags } from '@lezer/highlight';

type CodeEditorProps = {
  ariaLabel: string;
  language: string;
  onChange?: (value: string) => void;
  readOnly?: boolean;
  value: string;
};

const editorTheme = EditorView.theme(
  {
    '&': { backgroundColor: 'transparent', color: '#ffffff', fontSize: '12px' },
    '&.cm-focused': { outline: 'none' },
    '.cm-content': { caretColor: '#ffffff', fontFamily: 'var(--font-mono, monospace)' },
    '.cm-cursor': { borderLeftColor: '#ffffff' },
    '.cm-gutters': { backgroundColor: 'transparent', border: 'none', color: '#6b6b63' },
    '.cm-activeLine': { backgroundColor: 'rgba(255, 255, 255, 0.04)' },
    '.cm-activeLineGutter': { backgroundColor: 'transparent' },
    '.cm-selectionBackground, &.cm-focused .cm-selectionBackground': {
      backgroundColor: 'rgba(255, 255, 255, 0.15)',
    },
    '.cm-scroller': { maxHeight: '480px', minHeight: '240px', overflow: 'auto' },
  },
  { dark: true },
);

const highlightColours = HighlightStyle.define([
  { color: '#c792ea', tag: [tags.keyword, tags.modifier, tags.controlKeyword] },
  { color: '#c3e88d', tag: [tags.string, tags.special(tags.string)] },
  { color: '#f78c6c', tag: [tags.number, tags.bool, tags.null] },
  { color: '#82aaff', tag: [tags.function(tags.variableName), tags.definition(tags.variableName)] },
  { color: '#6b6b63', fontStyle: 'italic', tag: tags.comment },
]);

function languageExtension(language: string) {
  return language === 'javascript' ? javascript() : python();
}

/** The code editor of the sandbox page. It loads only there. */
export default function CodeEditor({
  ariaLabel,
  language,
  onChange,
  readOnly = false,
  value,
}: CodeEditorProps) {
  const hostRef = useRef<HTMLDivElement>(null);
  const viewRef = useRef<EditorView | null>(null);
  const valueRef = useRef(value);
  const onChangeRef = useRef(onChange);

  useEffect(() => {
    onChangeRef.current = onChange;
  }, [onChange]);

  useEffect(() => {
    valueRef.current = value;

    const view = viewRef.current;

    if (view && view.state.doc.toString() !== value) {
      view.dispatch({ changes: { from: 0, insert: value, to: view.state.doc.length } });
    }
  }, [value]);

  useEffect(() => {
    if (!hostRef.current) {
      return;
    }

    const view = new EditorView({
      parent: hostRef.current,
      state: EditorState.create({
        doc: valueRef.current,
        extensions: [
          basicSetup,
          languageExtension(language),
          syntaxHighlighting(highlightColours),
          editorTheme,
          EditorView.lineWrapping,
          EditorView.contentAttributes.of({ 'aria-label': ariaLabel }),
          EditorState.readOnly.of(readOnly),
          EditorView.editable.of(!readOnly),
          EditorView.updateListener.of((update) => {
            if (update.docChanged) {
              onChangeRef.current?.(update.state.doc.toString());
            }
          }),
        ],
      }),
    });

    viewRef.current = view;

    return () => {
      view.destroy();
      viewRef.current = null;
    };
  }, [ariaLabel, language, readOnly]);

  return <div ref={hostRef} className="rounded-lg bg-appBg p-1" />;
}
