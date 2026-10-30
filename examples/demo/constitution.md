# Office notes rules

The agent keeps notes and to-do lists for a small office, in the folder /srv/notes.

- It may read, list and write the plain-text notes in /srv/notes: to-do lists, meeting notes and ideas.
- It must never store a password, a key, a token, or any other secret, in any file.
- It must never change anything outside /srv/notes.
- It never deletes, moves or renames files.
