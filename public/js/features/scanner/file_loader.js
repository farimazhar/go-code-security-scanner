import { $ } from '../../common/utils.js';

/**
 * File Loader Controller
 * Handles drag-and-drop and file input loading for Go source files.
 */
export class FileLoaderController {
  constructor({ onFileLoaded }) {
    this.dropZone = $('#editorWrapper');
    this.fileInput = $('#fileInput');
    this.openFileBtn = $('#openFileBtn');
    this.fileBadge = $('#currentFileBadge');
    this.onFileLoaded = onFileLoaded;

    this.bindEvents();
  }

  bindEvents() {
    this.openFileBtn?.addEventListener('click', () => {
      this.fileInput?.click();
    });

    this.fileInput?.addEventListener('change', (e) => {
      const file = e.target.files?.[0];
      if (file) this.readFile(file);
    });

    if (this.dropZone) {
      ['dragenter', 'dragover'].forEach(eventName => {
        this.dropZone.addEventListener(eventName, (e) => {
          e.preventDefault();
          e.stopPropagation();
          this.dropZone.classList.add('drag-active');
        });
      });

      ['dragleave', 'drop'].forEach(eventName => {
        this.dropZone.addEventListener(eventName, (e) => {
          e.preventDefault();
          e.stopPropagation();
          this.dropZone.classList.remove('drag-active');
        });
      });

      this.dropZone.addEventListener('drop', (e) => {
        const file = e.dataTransfer?.files?.[0];
        if (file) this.readFile(file);
      });
    }
  }

  readFile(file) {
    if (!file.name.endsWith('.go') && !file.name.endsWith('.txt')) {
      alert('Please upload a Go source file (.go).');
      return;
    }

    const reader = new FileReader();
    reader.onload = (e) => {
      const content = e.target?.result;
      if (typeof content === 'string') {
        this.setFileBadge(file.name);
        if (this.onFileLoaded) {
          this.onFileLoaded(content, file.name);
        }
      }
    };
    reader.readAsText(file);
  }

  setFileBadge(name) {
    if (this.fileBadge) {
      if (name) {
        this.fileBadge.textContent = `📄 ${name}`;
        this.fileBadge.style.display = 'inline-block';
      } else {
        this.fileBadge.style.display = 'none';
      }
    }
  }
}
