<template>
  <q-page class="main-bg q-pa-xl flex justify-center">
    <div class="full-width" style="max-width: 1000px">
      <div class="row items-start q-mb-lg">
        <div class="col-12">
          <div class="header-label q-mb-xs">SECURITY ANALYSIS TOOL</div>
          <h1 class="page-title q-ma-none">Vulnerability Detector</h1>
        </div>
      </div>

      <q-card flat class="glass-card q-mb-sm">
        <q-card-section class="q-py-md">
          <div class="row items-center justify-between">
            <div class="section-label text-grey-8 uppercase">Upload Files</div>
            <q-btn flat dense @click="$router.push('/')" class="nav-btn"> Enter Text </q-btn>
          </div>
        </q-card-section>
      </q-card>

      <!-- Drop Zone -->
      <q-card flat class="upload-card q-mb-lg">
        <q-card-section class="q-pa-none">
          <div
            class="drop-zone flex flex-center column"
            :class="{ 'drop-zone--active': isDragging }"
            @dragover.prevent="isDragging = true"
            @dragleave.prevent="isDragging = false"
            @drop.prevent="onDrop"
            @click="$refs.fileInput.click()"
          >
            <div class="drop-title">Drop files here</div>
            <div class="drop-sub q-mt-xs">or click to browse</div>
            <input
              ref="fileInput"
              type="file"
              multiple
              accept=".py,.js,.jsx,.ts,.tsx,.html,.java, .go"
              style="display: none"
              @change="onFileInput"
            />
          </div>
        </q-card-section>
      </q-card>

      <!-- Queued Files -->
      <div v-if="uploadedFiles.length" class="q-mb-lg">
        <div class="section-label text-grey-6 q-mb-sm">
          QUEUED FILES ({{ uploadedFiles.length }})
        </div>
        <q-card flat class="file-list-card">
          <q-list separator>
            <q-item v-for="(f, i) in uploadedFiles" :key="i" class="file-item">
              <q-item-section>
                <q-item-label class="file-name">{{ f.name }}</q-item-label>
                <q-item-label caption class="file-size">{{ formatSize(f.size) }}</q-item-label>
              </q-item-section>
              <q-item-section side>
                <q-btn
                  flat
                  round
                  dense
                  icon="close"
                  size="sm"
                  color="grey-5"
                  @click="removeFile(i)"
                />
              </q-item-section>
            </q-item>
          </q-list>
        </q-card>
      </div>

      <q-btn
        unelevated
        @click="scanFiles"
        :loading="loading"
        :disable="!uploadedFiles.length"
        class="detect-btn full-width q-py-md text-weight-bold"
      >
        <span class="q-mr-sm">RUN DETECTION</span>
      </q-btn>

      <!-- Results -->
      <transition appear enter-active-class="animated fadeInUp">
        <div v-if="result" class="q-mt-xl">
          <div class="row q-col-gutter-lg q-mb-lg">
            <div class="col-12 col-md-4">
              <q-card flat class="result-stat-card text-center">
                <div class="stat-label">Security Grade</div>
                <div
                  class="text-h2 text-weight-bolder grade-display"
                  :class="`text-${getGradeColor(computedGrade)}`"
                >
                  {{ computedGrade }}
                </div>
                <div class="stat-sub">{{ computedScore }}/100</div>
              </q-card>
            </div>
            <div class="col-12 col-md-8">
              <q-card flat class="result-stat-card flex flex-center">
                <div class="row full-width text-center">
                  <div class="col-6">
                    <div class="text-h5 text-weight-bold stat-num">
                      {{ result.summary.total_files }}
                    </div>
                    <div class="stat-label">Files Checked</div>
                  </div>
                  <div class="col-6">
                    <div class="text-h5 text-weight-bold text-negative stat-num">
                      {{ activeCount }}
                    </div>
                    <div class="stat-label">Issues Found</div>
                  </div>
                </div>
              </q-card>
            </div>
          </div>

          <div v-for="file in result.files" :key="file.file">
            <div class="file-group-label q-mb-sm q-mt-lg">{{ file.file }}</div>
            <q-card
              v-for="(finding, idx) in file.findings"
              :key="idx"
              flat
              class="finding-card q-mb-md"
              :class="{ 'finding-card--dismissed': isDismissed(file.file, idx) }"
            >
              <q-card-section>
                <div class="row justify-between items-center q-mb-md">
                  <div class="row justify-center no-wrap q-gutter-sm">
                    <div class="finding-title">{{ finding.type }}</div>
                    <span v-if="isDismissed(file.file, idx)" class="dismissed-tag">DISMISSED</span>
                  </div>
                  <div class="row items-center q-gutter-sm">
                    <q-badge
                      :color="getSeverityColor(finding.severity)"
                      class="q-pa-sm severity-badge"
                      rounded
                    >
                      {{ finding.severity }}
                    </q-badge>
                    <q-btn
                      v-if="!isDismissed(file.file, idx)"
                      flat
                      dense
                      size="sm"
                      class="dismiss-btn"
                      @click="dismiss(file.file, idx)"
                      >Dismiss</q-btn
                    >
                    <q-btn
                      v-else
                      flat
                      dense
                      size="sm"
                      class="undo-btn"
                      @click="undoDismiss(file.file, idx)"
                      >Undo</q-btn
                    >
                  </div>
                </div>
                <div class="finding-desc q-mb-md">{{ finding.description }}</div>

                <div class="code-terminal q-mb-md">
                  <div class="terminal-line-label q-mb-xs">Line {{ finding.line }}</div>
                  <code>{{ finding.snippet }}</code>
                </div>

                <div class="remedy-banner q-pa-md">
                  <div class="remedy-title">FIX RECOMMENDATION</div>
                  <div class="remedy-body">{{ finding.recommendation }}</div>
                </div>

                <div v-if="finding.llm_fix" class="ai-remedy-banner q-pa-md q-mt-md">
                  <div class="row items-center q-mb-sm">
                    <div class="ai-remedy-title">AI FIX RECOMMENDATION</div>
                  </div>

                  <div class="ai-code-wrapper q-mb-sm">
                    <pre><code>{{ finding.llm_fix }}</code></pre>
                  </div>

                  <div class="ai-remedy-explanation">{{ finding.llm_explanation }}</div>
                </div>
              </q-card-section>
            </q-card>
          </div>
        </div>
      </transition>
    </div>
  </q-page>
</template>

<style lang="scss" scoped>
@import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;600;700&family=Syne:wght@400;700;800&display=swap');

* {
  font-family: 'Syne', sans-serif;
}

.main-bg {
  background: linear-gradient(135deg, #f5f5f5 0%, #121212 100%);
  min-height: 100vh;
}

.header-label {
  font-family: 'IBM Plex Mono', monospace;
  font-size: 11px;
  letter-spacing: 3px;
  color: #1a1a1a;
  text-transform: uppercase;
}

.page-title {
  font-family: 'Syne', sans-serif;
  font-size: 2rem;
  font-weight: 700;
  line-height: 1.3;
  color: #1a1a1a;
  letter-spacing: -0.5px;
}

.section-label {
  font-family: 'IBM Plex Mono', monospace;
  font-size: 12px;
  letter-spacing: 2.5px;
}

.glass-card {
  background: #ebebeb;
  border-radius: 20px 20px 5px 5px;
  border: 1px solid rgba(0, 0, 0, 0.05);
}

.nav-btn {
  font-family: 'IBM Plex Mono', monospace;
  font-size: 11px;
  letter-spacing: 1.5px;
  color: #1a1a1a;
  border-radius: 10px;
  padding: 6px 12px;
  background: rgba(0, 0, 0, 0.04);
  transition: all 0.2s;
  &:hover {
    color: #333;
    background: rgba(0, 0, 0, 0.08);
  }
}

.upload-card {
  border-radius: 5px 5px 25px 25px;
  background: white;
  overflow: hidden;
  border: 1px solid rgba(0, 0, 0, 0.5);
}

.drop-zone {
  min-height: 280px;
  cursor: pointer;
  border: 2px dashed #ddd;
  border-radius: 5px 5px 25px 25px;
  transition: all 0.2s ease;
  padding: 40px;

  &:hover,
  &.drop-zone--active {
    border-color: #aaa;
    background: #f5f5f5;
  }
}

.drop-icon {
  color: #ccc;
  transition: color 0.2s;
  .drop-zone:hover &,
  .drop-zone--active & {
    color: #999;
  }
}

.drop-title {
  font-family: 'Syne', sans-serif;
  font-size: 1.1rem;
  font-weight: 700;
  color: #555;
}

.drop-sub {
  font-family: 'IBM Plex Mono', monospace;
  font-size: 12px;
  color: #aaa;
}

.drop-hint {
  font-family: 'IBM Plex Mono', monospace;
  font-size: 10px;
  letter-spacing: 1.5px;
  color: #ccc;
  text-transform: uppercase;
}

/* ── File List ── */
.file-list-card {
  border-radius: 20px;
  background: white;
  overflow: hidden;
  border: 1px solid rgba(0, 0, 0, 0.06);
  box-shadow: 4px 4px 10px #e8e8e8;
}

.file-item {
  padding: 10px 16px;
}

.file-name {
  font-family: 'IBM Plex Mono', monospace;
  font-size: 13px;
  color: #333;
}

.file-size {
  font-family: 'IBM Plex Mono', monospace;
  font-size: 11px;
  color: #aaa;
}

.detect-btn {
  font-family: 'IBM Plex Mono', monospace;
  font-size: 13px;
  letter-spacing: 2px;
  background: linear-gradient(145deg, #ffffff, #e6e6e6);
  color: #222;
  border-radius: 15px;
  box-shadow: 0 10px 30px rgba(0, 0, 0, 0.3);
  transition: all 0.3s ease;
  border: 1px solid rgba(255, 255, 255, 0.1);
  &:hover {
    transform: translateY(-3px);
    box-shadow: 0 15px 35px rgba(0, 0, 0, 0.5);
    color: #000;
  }
}

/* ── Results ── */
.result-stat-card {
  border-radius: 25px;
  background: white;
  padding: 30px;
  box-shadow:
    10px 10px 20px #d9d9d9,
    -10px -10px 20px #ffffff;
}

.grade-display {
  font-family: 'Syne', sans-serif;
  font-size: 3rem;
  font-weight: 800;
  line-height: 1.2;
  margin: 8px 0;
}

.stat-label {
  font-family: 'IBM Plex Mono', monospace;
  font-size: 11px;
  letter-spacing: 1.5px;
  text-transform: uppercase;
  color: #999;
}

.stat-sub {
  font-family: 'IBM Plex Mono', monospace;
  font-size: 13px;
  color: #aaa;
  margin-top: 4px;
}

.stat-num {
  font-family: 'Syne', sans-serif;
  font-weight: 700;
}

.file-group-label {
  font-family: 'IBM Plex Mono', monospace;
  font-size: 11px;
  letter-spacing: 2px;
  text-transform: uppercase;
  color: white;
  border-left: 3px solid #ddd;
  padding-left: 10px;
}

.finding-card {
  border-radius: 25px;
  background: white;
  box-shadow: 6px 6px 12px #e0e0e0;
  border: 1px solid rgba(0, 0, 0, 0.03);
}

.finding-title {
  font-family: 'Syne', sans-serif;
  font-size: 1.1rem;
  font-weight: 700;
  color: #1a1a1a;
}

.severity-badge {
  font-family: 'IBM Plex Mono', monospace;
  font-size: 11px;
  letter-spacing: 1px;
}

.finding-desc {
  font-family: 'Syne', sans-serif;
  font-size: 0.9rem;
  color: #555;
  line-height: 1.6;
}

.code-terminal {
  background: #1a1a1a;
  color: #eee;
  padding: 15px;
  border-radius: 12px;
  font-family: 'IBM Plex Mono', monospace;
  font-size: 13px;
  code {
    font-family: 'IBM Plex Mono', monospace;
  }
}

.terminal-line-label {
  font-family: 'IBM Plex Mono', monospace;
  font-size: 10px;
  letter-spacing: 1.5px;
  color: #666;
  text-transform: uppercase;
}

.remedy-banner {
  background: #f1f8e9;
  border-radius: 12px;
  border-left: 6px solid #81c784;
}

.remedy-title {
  font-family: 'IBM Plex Mono', monospace;
  font-size: 10px;
  letter-spacing: 2px;
  font-weight: 600;
  color: #555;
  margin-bottom: 6px;
  text-transform: uppercase;
}

.remedy-body {
  font-family: 'Syne', sans-serif;
  font-size: 0.88rem;
  color: #444;
  line-height: 1.6;
}

.finding-card--dismissed {
  opacity: 0.45;
  background: #f7f7f7;
  box-shadow: none;
  border: 1px dashed rgba(0, 0, 0, 0.08);
}
.dismissed-tag {
  font-family: 'IBM Plex Mono', monospace;
  font-size: 9px;
  letter-spacing: 2px;
  color: #bbb;
  background: #eee;
  border-radius: 6px;
  padding: 2px 8px;
}
.dismiss-btn {
  font-family: 'IBM Plex Mono', monospace;
  font-size: 10px;
  letter-spacing: 1.5px;
  color: #aaa;
  border: 1px solid #ddd;
  border-radius: 8px;
  padding: 3px 10px;
  &:hover {
    color: #555;
    border-color: #bbb;
    background: #f5f5f5;
  }
}
.undo-btn {
  font-family: 'IBM Plex Mono', monospace;
  font-size: 10px;
  letter-spacing: 1.5px;
  color: #81c784;
  border: 1px solid #81c784;
  border-radius: 8px;
  padding: 3px 10px;
  &:hover {
    color: #fff;
    background: #81c784;
  }
}

.ai-remedy-banner {
  background: #f0f4ff;
  border-radius: 12px;
  border-left: 6px solid #5c6bc0;
}

.ai-remedy-title {
  font-family: 'IBM Plex Mono', monospace;
  font-size: 10px;
  letter-spacing: 2px;
  font-weight: 700;
  color: #3f51b5;
  text-transform: uppercase;
}

.ai-code-wrapper {
  background: #282c34;
  color: #abb2bf;
  padding: 12px;
  border-radius: 8px;
  font-family: 'IBM Plex Mono', monospace;
  font-size: 12px;
  overflow-x: auto;

  pre {
    margin: 0;
    white-space: pre-wrap;
    word-break: break-all;
  }
}

.ai-remedy-explanation {
  font-family: 'Syne', sans-serif;
  font-size: 0.88rem;
  color: #3f4756;
  line-height: 1.6;
  font-style: italic;
}
</style>

<script>
import { ref } from 'vue'
import axios from 'axios'
import { useDismiss } from './useDismiss'

export default {
  setup() {
    const uploadedFiles = ref([])
    const isDragging = ref(false)
    const result = ref(null)
    const {
      isDismissed,
      dismiss,
      undoDismiss,
      resetDismissed,
      computedScore,
      computedGrade,
      activeCount,
    } = useDismiss(result)
    const loading = ref(false)

    const addFiles = (files) => {
      const allowed = ['.py', '.js', '.jsx', '.ts', '.tsx', '.html', '.java', '.go']
      for (const f of files) {
        const ext = '.' + f.name.split('.').pop().toLowerCase()
        if (allowed.includes(ext) && !uploadedFiles.value.find((u) => u.name === f.name)) {
          uploadedFiles.value.push(f)
        }
      }
    }

    const onFileInput = (e) => addFiles(Array.from(e.target.files))
    const onDrop = (e) => {
      isDragging.value = false
      addFiles(Array.from(e.dataTransfer.files))
    }
    const removeFile = (i) => uploadedFiles.value.splice(i, 1)

    const formatSize = (bytes) => {
      if (bytes < 1024) return bytes + ' B'
      if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB'
      return (bytes / (1024 * 1024)).toFixed(1) + ' MB'
    }

    const readFile = (file) =>
      new Promise((resolve, reject) => {
        const reader = new FileReader()
        reader.onload = (e) => resolve(e.target.result)
        reader.onerror = reject
        reader.readAsText(file)
      })

    const scanFiles = async () => {
      if (!uploadedFiles.value.length) return
      loading.value = true
      // result.value = null
      resetDismissed()
      try {
        const filePayloads = await Promise.all(
          uploadedFiles.value.map(async (f) => ({
            path: f.name,
            content: await readFile(f),
          })),
        )
        const response = await axios.post('http://localhost:8080/scan', { files: filePayloads })
        result.value = response.data
      } catch (error) {
        console.error(error)
      } finally {
        loading.value = false
      }
    }

    const getSeverityColor = (sev) => {
      const s = sev.toLowerCase()
      if (s === 'critical') return 'red-9'
      if (s === 'medium' || s === 'high') return 'orange-8'
      return 'grey-7'
    }

    const getGradeColor = (grade) => {
      const colors = { A: 'green-7', B: 'light-green-7', C: 'orange-7', D: 'red-7' }
      return colors[grade] || 'grey-7'
    }

    return {
      uploadedFiles,
      isDragging,
      result,
      loading,
      onFileInput,
      onDrop,
      removeFile,
      formatSize,
      scanFiles,
      getSeverityColor,
      getGradeColor,
      isDismissed,
      dismiss,
      undoDismiss,
      computedScore,
      computedGrade,
      activeCount,
    }
  },
}
</script>
