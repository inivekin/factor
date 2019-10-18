/* :folding=explicit:collapseFolds=1: */

/*
 * $Id$
 *
 * Copyright (C) 2004 Slava Pestov.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND
 * FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * DEVELOPERS AND CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

package factor.jedit;

import factor.*;
import java.awt.event.*;
import java.awt.*;
import java.io.IOException;
import javax.swing.*;
import org.gjt.sp.jedit.textarea.JEditTextArea;
import org.gjt.sp.jedit.*;
import org.gjt.sp.util.Log;

public class TextAreaPopup extends JWindow
{
	private View view;
	private JTextArea preview;
	
	//{{{ TextAreaPopup constructor
	public TextAreaPopup(JEditTextArea textArea, String text)
	{
		super(GUIUtilities.getView(textArea));
		this.view = GUIUtilities.getView(textArea);
		preview = new JTextArea(text);
		preview.setEditable(false);
		getContentPane().add(BorderLayout.CENTER,new JScrollPane(preview));
		pack();

		KeyHandler keyHandler = new KeyHandler();
		addKeyListener(keyHandler);
		preview.addKeyListener(keyHandler);
		view.setKeyEventInterceptor(keyHandler);

		GUIUtilities.requestFocus(this,preview);
		
		positionAtCaret(textArea);
		setVisible(true);
	} //}}}

	//{{{ positionAtCaret() method
	private void positionAtCaret(JEditTextArea textArea)
	{
		int line = textArea.getCaretLine();
		String lineText = textArea.getLineText(line);
		int caret = textArea.getCaretPosition()
			- textArea.getLineStartOffset(line);
		int start = FactorPlugin.getWordStartOffset(lineText,caret);
		Point loc = textArea.offsetToXY(line,start,new Point(0,0));
		loc.y += textArea.getPainter().getFontMetrics().getHeight();
		SwingUtilities.convertPointToScreen(loc,textArea.getPainter());
		setLocation(loc);
	} //}}}

	//{{{ KeyHandler class
	class KeyHandler extends KeyAdapter
	{
		//{{{ keyPressed() method
		public void keyPressed(KeyEvent evt)
		{
			switch(evt.getKeyCode())
			{
			case KeyEvent.VK_TAB:
			case KeyEvent.VK_ENTER:
			case KeyEvent.VK_ESCAPE:
				dispose();
				view.setKeyEventInterceptor(null);
				evt.consume();
				break;
			}
		} //}}}
	} //}}}
}