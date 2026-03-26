const routes = [
  {
    path: '/',
    component: () => import('layouts/MainLayout.vue'),
    children: [
      { path: '', component: () => import('pages/ScanPage.vue') },
      { path: '/upload', component: () => import('pages/UploadPage.vue') },
    ],
  },
]

export default routes
