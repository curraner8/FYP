<template>
  <q-page padding>
    <div class="q-pa-md">
      <h4>Code Security Scanner</h4>

      <q-input v-model="filename" label="Filename (e.g., app.js)" outlined class="q-mb-md" />

      <q-input
        v-model="code"
        type="textarea"
        label="Paste your code here"
        outlined
        rows="15"
        class="q-mb-md"
      />

      <q-btn
        color="primary"
        label="Scan Code"
        @click="scanCode"
        :loading="loading"
        class="q-mb-md"
      />

      <div v-if="result" class="q-mt-md">
        <q-card>
          <q-card-section>
            <div class="text-h6">
              Score: {{ result.score }} / 100
              <q-badge :color="getGradeColor(result.grade)"> Grade {{ result.grade }} </q-badge>
            </div>
            <p>Files Scanned: {{ result.summary.total_files }}</p>
            <p>Files with Issues: {{ result.summary.files_with_issues }}</p>
          </q-card-section>
        </q-card>

        <q-card v-for="file in result.files" :key="file.file" class="q-mt-md">
          <q-card-section>
            <div class="text-h6">{{ file.file }}</div>

            <q-list bordered separator>
              <q-item v-for="(finding, idx) in file.findings" :key="idx">
                <q-item-section>
                  <q-item-label>
                    <q-badge :color="getSeverityColor(finding.severity)">
                      {{ finding.severity }}
                    </q-badge>
                    {{ finding.type }}
                  </q-item-label>
                  <q-item-label caption>
                    Line {{ finding.line }}: {{ finding.description }}
                  </q-item-label>
                  <q-item-label caption class="text-grey-8">
                    Code: <code>{{ finding.snippet }}</code>
                  </q-item-label>
                  <q-item-label caption class="text-green-8">
                    {{ finding.recommendation }}
                  </q-item-label>
                </q-item-section>
              </q-item>
            </q-list>
          </q-card-section>
        </q-card>
      </div>
    </div>
  </q-page>
</template>

<script>
import { ref } from 'vue'
import axios from 'axios'

export default {
  name: 'ScanPage',
  setup() {
    const filename = ref('test.js')
    const code = ref('')
    const result = ref(null)
    const loading = ref(false)

    const scanCode = async () => {
      if (!code.value) {
        alert('Please enter some code to scan')
        return
      }

      loading.value = true
      try {
        const response = await axios.post('http://localhost:8080/scan?ts=' + Date.now(), {
          files: [
            {
              path: filename.value,
              content: code.value,
            },
          ],
        })
        result.value = response.data
      } catch (error) {
        console.error('Scan failed:', error)
        alert('Scan failed: ' + error.message)
      } finally {
        loading.value = false
      }
    }

    const getSeverityColor = (severity) => {
      const colors = {
        critical: 'red',
        medium: 'orange',
        low: 'yellow-8',
      }
      return colors[severity] || 'grey'
    }

    const getGradeColor = (grade) => {
      const colors = {
        A: 'green',
        B: 'light-green',
        C: 'orange',
        D: 'red',
      }
      return colors[grade] || 'grey'
    }

    return {
      filename,
      code,
      result,
      loading,
      scanCode,
      getSeverityColor,
      getGradeColor,
    }
  },
}
</script>
